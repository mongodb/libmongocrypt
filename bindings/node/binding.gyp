{
  'targets': [
    {
      'target_name': 'mongocrypt',
      'include_dirs': [
          '<!(node -e "require(\'nan\')")'
      ],
      'sources': [
        'src/mongocrypt.cc'
      ],
      'link_settings': {
        'libraries': [
          '-lmongocrypt'
          # '<(module_root_dir)/deps/libmongocrypt/lib/libmongocrypt-static.a',
          # '/usr/local/lib/libbson-static-1.0.a'
        ]
      }
    }
  ]
}