{
  'targets': [{
    'target_name': 'mongocrypt',
    'include_dirs': [
        '<!(node -e "require(\'nan\')")'
    ],
    'variables': {
        'variables': {
            'build_type%': "dynamic",
        },
        'conditions': [
          ['OS=="win"', {
            'build_type' : "<!(echo %BUILD_TYPE%)"
          }],
          ['OS!="win"', {
            'build_type' : "<!(echo $BUILD_TYPE)",
          }]
        ]
    },
    'sources': [
      'src/mongocrypt.cc'
    ],
    'xcode_settings': {
      'MACOSX_DEPLOYMENT_TARGET': '10.12',
      'OTHER_CFLAGS': [
        "-std=c++11",
        "-stdlib=libc++"
      ],
    },
    'conditions': [
      ['build_type=="dynamic"', {
        'link_settings': {
          'libraries': [
            '-lmongocrypt'
          ]
        }
      }],
      ['build_type!="dynamic"', {
        'conditions': [
          ['OS!="win"', {
            'include_dirs': [
              '<(module_root_dir)/deps/include'
            ],
            'link_settings': {
              'libraries': [
                '<(module_root_dir)/deps/lib/libmongocrypt-static.a',
                '<(module_root_dir)/deps/lib/libkms_message-static.a',
                '<(module_root_dir)/deps/lib/libbson-static-1.0.a'
              ]
            }
          }],
          ['OS=="win"', {
            'defines': [ 'MONGOCRYPT_STATIC_DEFINE' ],
            'include_dirs': [
              '<(module_root_dir)/deps/include'
            ],
            'link_settings': {
              'libraries': [
                '<(module_root_dir)/deps/lib/mongocrypt-static.lib',
                '<(module_root_dir)/deps/lib/kms_message-static.lib',
                '<(module_root_dir)/deps/lib/bson-static-1.0.lib',
                '-lws2_32'
              ]
            }
          }]
        ]
      }]
    ]
  }]
}
