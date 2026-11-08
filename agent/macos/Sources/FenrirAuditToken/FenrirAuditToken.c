#include "FenrirAuditToken.h"
#include <bsm/libbsm.h>

pid_t fenrir_audit_pid(audit_token_t token) {
    return audit_token_to_pid(token);
}
