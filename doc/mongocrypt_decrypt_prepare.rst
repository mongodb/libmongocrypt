mongocrypt_decrypt_prepare
==========================

Synopsis
--------
.. code::

  #include <mongocrypt.h>

  bool
  mongocrypt_decrypt_prepare (mongocrypt_t *crypt,
                              const mongocrypt_binary_t* encrypted_docs,
                              uint32_t num_docs,
                              mongocrypt_datakey_request_t **requests,
                              mongocrypt_error_t *error);


Parameters
----------
- ``crypt``: the :ref:`mongocrypt_t:mongocrypt_t` handle.
- ``encrypted_docs``: a C array pointing to BSON documents needing decryption. These should be documents returned by a MongoDB cursor.
- ``num_docs``: the number of BSON documents in ``docs``.
- ``requests``: set to a list of keys libmongocrypt requires to do decryption in :ref:`mongocrypt_decrypt_finish:mongocrypt_decrypt_finish`. Caller must call mongocrypt_datakey_request_destroy after.
- ``error``: set to an error. The caller must call mongocrypt_error_destroy after (even if no error occurred).

.. Why a C array and not a BSON array? For document sequences.

Returns
-------
True on success, false on failure. On failure, ``error`` is populated.

.. Description
.. -----------

.. Example
.. -------

See Also
--------
- :ref:`mongocrypt_decrypt_finish:mongocrypt_decrypt_finish`: The next call in the sequence to decrypt.