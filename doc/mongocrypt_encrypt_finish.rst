mongocrypt_encrypt_finish
=========================

Synopsis
--------
.. code::

  #include <mongocrypt.h>

  bool
  mongocrypt_encrypt_finish (mongocrypt_t *crypt,
                             const mongocrypt_binary_t *marked_cmd,
                             const mongocrypt_binary_t *datakeys,
                             mongocrypt_binary_t *encrypted_cmd,
                             mongocrypt_error_t *error);

Parameters
----------
- ``crypt``: the :ref:`mongocrypt_t:mongocrypt_t` handle.
- ``marked_cmd``: a BSON document representing a MongoDB command, where values requiring encryption have been replaced with FLE markings.
- ``datakeys``: a BSON document containing data keys requested before.
- ``encrypted_cmd``: set to a transformed version of ``marked_cmd``, where FLE markings have been replaced by FLE ciphertexts.
- ``error``: set to an error. The caller must call mongocrypt_error_destroy after (even if no error occurred).

.. include:: include/datakeys.txt

Returns
-------
True on success, false on failure. On failure, ``error`` is populated.

See Also
--------
- :ref:`mongocrypt_encrypt_prepare:mongocrypt_encrypt_prepare`: The previous call in the sequence to encrypt.