// SPDX-License-Identifier: GPL-2.0-or-later
// Twinet's optional command reports. Included only by vtysh_main.c.
#include <json-c/json.h>
#include <sys/random.h>
#include <errno.h>
#include <stdint.h>

static int collection_fd = -1;
static char collection_nonce[33], collection_process[33];
static unsigned long collection_message, collection_command;
static bool collection_active;

void twinet_collection_end(int result);

static void collection_string(struct json_object *o, const char *key, const char *value)
{
	json_object_object_add(o, key, json_object_new_string(value ? value : ""));
}

static const char *collection_mode(void)
{
	struct cmd_node *node = vector_lookup(cmdvec, vty->node);
	return node && node->name ? node->name : "unknown";
}

static void collection_send(struct json_object *o)
{
	const char *json = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
	size_t len = strlen(json), count = (len + 1023) / 1024;
	static const char hex[] = "0123456789abcdef";
	unsigned long message = ++collection_message;
	if (len > 32768) {
		fprintf(stderr, "twinet: command report exceeds 32768 bytes\n");
		_exit(125);
	}
	for (size_t i = 0; i < count; i++) {
		char frame[2300];
		size_t n = (size_t)snprintf(frame, sizeof(frame),
			"\033]777;twinet=%s;app;1;%s;%lu;%zu;%zu;",
			collection_nonce, collection_process, message, i, count);
		size_t end = (i + 1) * 1024 < len ? (i + 1) * 1024 : len;
		for (size_t j = i * 1024; j < end; j++) {
			unsigned char c = (unsigned char)json[j];
			frame[n++] = hex[c >> 4];
			frame[n++] = hex[c & 15];
		}
		frame[n++] = '\007';
		ssize_t written;
		do { written = write(collection_fd, frame, n); } while (written < 0 && errno == EINTR);
		if (written != (ssize_t)n)
			_exit(125);
	}
	json_object_put(o);
}

static struct json_object *collection_event(const char *kind)
{
	struct json_object *o = json_object_new_object();
	char id[80];
	snprintf(id, sizeof(id), "%s:%lu", collection_process, collection_command);
	collection_string(o, "type", kind);
	collection_string(o, "invocation", collection_process);
	collection_string(o, "command_id", id);
	collection_string(o, "application", "vtysh");
	collection_string(o, "application_version", FRR_VERSION);
	json_object_object_add(o, "process_id", json_object_new_int64(getpid()));
	return o;
}

static void collection_shutdown(void)
{
	if (collection_fd < 0)
		return;
	if (collection_active) {
		struct json_object *o = collection_event("command_incomplete");
		collection_string(o, "reason", "vtysh exited before reporting a command result");
		collection_send(o);
	}
	collection_send(collection_event("application_end"));
}

static void collection_init(void)
{
	static bool initialized;
	if (initialized)
		return;
	initialized = true;
	const char *nonce = getenv("TWINET_COLLECTION_NONCE");
	const char *fd = getenv("TWINET_COLLECTION_FD");
	if (!nonce || strlen(nonce) != 32 || strspn(nonce, "0123456789abcdef") != 32 || !fd || strcmp(fd, "9"))
		return;
	unsigned char random[16];
	if (getrandom(random, sizeof(random), 0) != sizeof(random))
		_exit(125);
	for (size_t i = 0; i < sizeof(random); i++)
		snprintf(collection_process + 2 * i, 3, "%02x", random[i]);
	memcpy(collection_nonce, nonce, 33);
	collection_fd = 9;
	atexit(collection_shutdown);
	struct json_object *o = collection_event("application_start");
	collection_string(o, "coverage", "interactive-and-command-arguments");
	collection_send(o);
}

// FRR's top-level exit/quit command exits the process without returning.
void twinet_collection_end(int result)
{
	if (collection_fd < 0 || !collection_active)
		return;
	struct json_object *o = collection_event("command_end");
	json_object_object_add(o, "result_code", json_object_new_int(result));
	collection_string(o, "mode_after", collection_mode());
	collection_send(o);
	collection_active = false;
}

static int collected_execute(const char *line, int pager, const char *input_kind)
{
	collection_init();
	if (collection_fd >= 0 && line && strspn(line, " \t\r\n") != strlen(line)) {
		collection_command++;
		collection_active = true;
		struct json_object *o = collection_event("command_start");
		collection_string(o, "command", line);
		collection_string(o, "mode_before", collection_mode());
		collection_string(o, "input_kind", input_kind);
		collection_send(o);
	}
	int result = pager ? vtysh_execute(line) : vtysh_execute_no_pager(line);
	twinet_collection_end(result);
	return result;
}
