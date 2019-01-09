mongocrypt_encrypt_prepare
==========================

Synopsis
--------
.. code::

  #include <mongocrypt.h>

  bool
  mongocrypt_encrypt_prepare (mongocrypt_t *crypt,
                              const mongocrypt_binary_t *schema,
                              const mongocrypt_binary_t *cmd,
                              mongocrypt_binary_t **marked_cmd,
                              mongocrypt_datakey_request_t **requests,
                              mongocrypt_error_t *error);


Parameters
----------
- ``crypt``: the :ref:`mongocrypt_t:mongocrypt_t` handle.
- ``schema``: a BSON document representing a JSONSchema for the collection.
- ``cmd``: a BSON document representing a MongoDB command requiring encryption.
- ``marked_cmd``: set to a transformed version of ``cmd``. Fields requiring encryption in have been replaced with FLE markings. If nothing was marked, this is set to ``NULL``. Caller must call mongocrypt_binary_destroy after.
- ``requests``: set to a list of keys libmongocrypt requires to do encryption in :ref:`mongocrypt_encrypt_finish:mongocrypt_encrypt_finish`. Caller must call mongocrypt_datakey_request_destroy after.
- ``error``: set to an error. The caller must call mongocrypt_error_destroy after (even if no error occurred).

Returns
-------
True on success, false on failure. On failure, ``error`` is populated.

.. Description
.. -----------

.. Example
.. -------

See Also
--------
- :ref:`mongocrypt_encrypt_finish:mongocrypt_encrypt_finish`: The next call in the sequence to encrypt.