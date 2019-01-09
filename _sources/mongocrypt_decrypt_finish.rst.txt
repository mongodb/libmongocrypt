mongocrypt_decrypt_finish
=========================

Synopsis
--------
.. code::

  #include <mongocrypt.h>

  bool
  mongocrypt_decrypt_finish (mongocrypt_t *crypt,
                             const mongocrypt_binary_t *encrypted_docs,
                             uint32_t num_docs,
                             const mongocrypt_binary_t *datakeys,
                             mongocrypt_binary_t **docs,
                             mongocrypt_error_t *error);

Parameters
----------
- ``crypt``: the :ref:`mongocrypt_t:mongocrypt_t` handle.
- ``encrypted_docs``: a C array pointing to BSON documents needing decryption. These should be documents returned by a MongoDB cursor.
- ``num_docs``: the number of BSON documents in ``docs``.
- ``datakeys``: a BSON document containing data keys requested before.
- ``docs``: points to a C array of length num_docs. Documents that are decrypted are set in this array. Documents not requiring decryption set the array index to NULL.
- ``error``: set to an error. The caller must call mongocrypt_error_destroy after (even if no error occurred).

.. include:: include/datakeys.txt

Returns
-------
True on success, false on failure. On failure, ``error`` is populated.

See Also
--------
- :ref:`mongocrypt_decrypt_prepare:mongocrypt_decrypt_prepare`: The previous call in the sequence to decrypt.