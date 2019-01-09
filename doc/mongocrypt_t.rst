mongocrypt_t
============

Synopsis
--------

.. code-block:: c

  #include <mongocrypt.h>

  typedef struct _mongocrypt_t mongocrypt_t;

The handle to libmongocrypt.

Description
-----------

All operations, except for creating and destroying a mongocrypt_t handle, are thread safe.

Drivers should create a mongocrypt_t handle upon construction of a MongoClient with :ref:`mongocrypt_new:mongocrypt_new`, and destroy during MongoClient destruction with :ref:`mongocrypt_destroy:mongocrypt_destroy`.

Functions
---------

.. toctree::
   :maxdepth: 1

   mongocrypt_new
   mongocrypt_destroy
   mongocrypt_encrypt_prepare
   mongocrypt_encrypt_finish
   mongocrypt_decrypt_prepare
   mongocrypt_decrypt_finish