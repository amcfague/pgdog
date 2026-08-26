#define _POSIX_C_SOURCE 200809L

#include <libpq-fe.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *bearer_token;
static const char *expected_discovery;
static const char *expected_scope;
static const char *hook_marker;
static int hook_calls;

static void cleanup_token(PGconn *conn, PGoauthBearerRequest *request) {
    (void) conn;
    free(request->token);
    request->token = NULL;
}

static int auth_data(PGauthData type, PGconn *conn, void *data) {
    (void) conn;
    if (type != PQAUTHDATA_OAUTH_BEARER_TOKEN) {
        return 0;
    }

    PGoauthBearerRequest *request = data;
    hook_calls++;
    if (expected_discovery != NULL &&
        (request->openid_configuration == NULL ||
         strcmp(request->openid_configuration, expected_discovery) != 0)) {
        fprintf(stderr, "unexpected discovery URL\n");
        return 0;
    }
    if (expected_scope != NULL &&
        (request->scope == NULL || strcmp(request->scope, expected_scope) != 0)) {
        fprintf(stderr, "unexpected OAuth scope\n");
        return 0;
    }
    if (hook_marker != NULL) {
        FILE *marker = fopen(hook_marker, "w");
        if (marker != NULL) {
            fputs("called\n", marker);
            fclose(marker);
        }
    }

    request->token = strdup(bearer_token);
    if (request->token == NULL) {
        return 0;
    }
    request->cleanup = cleanup_token;
    return 1;
}

static int query_ok(PGconn *conn) {
    PGresult *result = PQexec(conn, "SELECT 1");
    int ok = PQresultStatus(result) == PGRES_TUPLES_OK &&
             PQntuples(result) == 1 &&
             strcmp(PQgetvalue(result, 0, 0), "1") == 0;
    PQclear(result);
    return ok;
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr,
                "usage: oauth_client CONNINFO TOKEN MODE DISCOVERY SCOPE MARKER\n");
        return 2;
    }

    const char *conninfo = argv[1];
    bearer_token = argv[2];
    const char *mode = argv[3];
    expected_discovery = strcmp(argv[4], "-") == 0 ? NULL : argv[4];
    expected_scope = strcmp(argv[5], "-") == 0 ? NULL : argv[5];
    hook_marker = strcmp(argv[6], "-") == 0 ? NULL : argv[6];

    PQsetAuthDataHook(auth_data);
    PGconn *conn = PQconnectdb(conninfo);
    if (conn == NULL) {
        fprintf(stderr, "PQconnectdb returned NULL\n");
        return 1;
    }

    int connected = PQstatus(conn) == CONNECTION_OK;
    if (strcmp(mode, "success") == 0) {
        if (!connected || !query_ok(conn) || hook_calls == 0) {
            fprintf(stderr, "OAuth connection failed: %s", PQerrorMessage(conn));
            PQfinish(conn);
            return 1;
        }
    } else if (strcmp(mode, "auth-failure") == 0) {
        const char *error = PQerrorMessage(conn);
        if (connected || strstr(error, "OAuth authentication failed") == NULL ||
            strstr(error, bearer_token) != NULL) {
            fprintf(stderr, "unexpected OAuth failure: %s", error);
            PQfinish(conn);
            return 1;
        }
    } else if (strcmp(mode, "preauth-failure") == 0) {
        if (connected || hook_calls != 0) {
            fprintf(stderr, "expected failure before token delivery\n");
            PQfinish(conn);
            return 1;
        }
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        PQfinish(conn);
        return 2;
    }

    PQfinish(conn);
    return 0;
}
