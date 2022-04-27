#include "nanomq.h"
#include "msquic.h"
#include "quic_client.h"

struct work {
	enum { INIT, RECV, WAIT, SEND } state;
	nng_aio *aio;
	nng_msg *msg;
	nng_ctx  ctx;
};

static char * help_info = "test for quic\n\n";

static int               nwork  = 32;

static void
quic_fatal(const char *msg, int rv)
{
	fprintf(stderr, "%s: %s\n", msg, nng_strerror(rv));
}

void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	printf("%s: disconnected!\n", __FUNCTION__);
}

void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	debug_msg("%s: connected!", __FUNCTION__);
	nng_socket sock = *(nng_socket *) arg;

	nng_mqtt_topic_qos topic_qos[1];

	char *sub_topic = "topic";

	debug_msg("topic: %s", sub_topic);
	topic_qos[0].qos          = 0;
	topic_qos[0].topic.buf    = (uint8_t *) sub_topic;
	topic_qos[0].topic.length = strlen(sub_topic);

	size_t topic_qos_count =
	    sizeof(topic_qos) / sizeof(nng_mqtt_topic_qos);

	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);
	nng_mqtt_msg_set_subscribe_topics(msg, topic_qos, topic_qos_count);

	// Send subscribe message
	int rv = 0;
	rv     = nng_sendmsg(sock, msg, NNG_FLAG_NONBLOCK);
	if (rv != 0) {
		quic_fatal("nng_sendmsg", rv);
	}
}

void
quic_sub_cb(void *arg)
{
	struct work *work = arg;
	nng_msg *    msg;
	int          rv;

	switch (work->state) {
	case INIT:
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;
	case RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			quic_fatal("nng_send_aio", rv);
		}
		msg = nng_aio_get_msg(work->aio);

		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;
	default:
		quic_fatal("bad state!", NNG_ESTATE);
		break;
	}
}

struct work *
proxy_alloc_work(nng_socket sock)
{
	struct work *w;
	int          rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		quic_fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, quic_sub_cb, w)) != 0) {
		quic_fatal("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		quic_fatal("nng_ctx_open", rv);
	}
	w->state = INIT;
	return (w);
}

int
client_publish(nng_socket sock, const char *topic, uint8_t *payload,
    uint32_t payload_len, uint8_t qos, bool verbose)
{
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, 0);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_retain(pubmsg, 0);
	nng_mqtt_msg_set_publish_payload(
	    pubmsg, (uint8_t *) payload, payload_len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);

	// printf("Publishing '%s' to '%s' ...\n", payload, topic);
	if ((rv = nng_sendmsg(sock, pubmsg, NNG_FLAG_NONBLOCK)) != 0) {
		quic_fatal("nng_sendmsg", rv);
	}

	return rv;
}

// Config for msquic
const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };
const uint16_t UdpPort = 4567;
const uint64_t IdleTimeoutMs = 1000;
const uint32_t SendBufferLength = 100;
const QUIC_API_TABLE* MsQuic;
const QUIC_API_TABLE* MsQuic;
HQUIC Registration;
HQUIC Configuration;

void
quic_open()
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

	printf("msquic is started.\n");

Error:

    if (MsQuic != NULL) {
        if (Configuration != NULL) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != NULL) {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }
}

int
client(const char *url, nng_socket *sock_ret)
{
	nng_socket   sock;
	nng_dialer   dialer;
	int          rv;
	struct work *works[nwork];

	if ((rv = nng_mqtt_client_open(&sock)) != 0) {
		quic_fatal("nng_socket", rv);
		return rv;
	}

	*sock_ret = sock;

	// Quic settings
	quic_open();

	for (int i = 0; i < nwork; i++) {
		works[i] = proxy_alloc_work(sock);
	}

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);

	nng_mqtt_set_connect_cb(sock, connect_cb, sock_ret);
	nng_mqtt_set_disconnect_cb(sock, disconnect_cb, NULL);

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		quic_fatal("nng_dialer_create", rv);
	}

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	for (int i = 0; i < nwork; i++) {
		quic_sub_cb(works[i]);
	}

	return 0;
}

int
quic_run()
{
	nng_socket sock;
	char * mqtt_url = "mqtt-tcp://0.0.0.0:1883";
	char * text = malloc(sizeof(char) * 20);

	client(mqtt_url, &sock);

	while (1) {
		fgets(text, 20, stdin);
		client_publish(sock, "topic",
		    (uint8_t *) text, strlen(text), 0, false);
	}
}

int
quic_start(int argc, char **argv)
{
	quic_run();
	return 0;
}

int
quic_dflt(int argc, char **argv)
{
	printf("%s", help_info);
	return 0;
}
