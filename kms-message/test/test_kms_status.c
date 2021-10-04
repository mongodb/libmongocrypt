#include "test_kms_request.h"

#include "src/kms_message/kms_message.h"
#include "src/kms_status_private.h"

void kms_status_test (void) {
   kms_status_t* status;
   const char* str;

   status = kms_status_new ();
   ASSERT (kms_status_ok (status));

   kms_status_errorf (status, "error: %s", "foo");
   ASSERT (!kms_status_ok (status));
   str = kms_status_to_string (status);
   ASSERT_CMPSTR (str, "error: foo");

   kms_status_reset (status);
   ASSERT (kms_status_ok (status));
   kms_status_destroy (status);
}
