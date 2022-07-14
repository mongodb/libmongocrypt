{
  'targets': [{
    'target_name': 'mongocrypt',
    'include_dirs': [
        "<!(node -p \"require('node-addon-api').include_dir\")",
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
      'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
      'CLANG_CXX_LIBRARY': 'libc++',
      'MACOSX_DEPLOYMENT_TARGET': '10.12'
    },
    'cflags!': [ '-fno-exceptions' ],
    'cflags_cc!': [ '-fno-exceptions' ],
    'msvs_settings': {
      'VCCLCompilerTool': { 'ExceptionHandling': 1 },
    },
    'conditions': [
      ['OS=="mac"', {
          'cflags+': ['-fvisibility=hidden'],
          'xcode_settings': {
            'GCC_SYMBOLS_PRIVATE_EXTERN': 'YES', # -fvisibility=hidden
          }
      }],
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
                '<(module_root_dir)/deps/lib/libbson-static-for-libmongocrypt.a'
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
                '<(module_root_dir)/deps/lib/bson-static-for-libmongocrypt.lib',
                '-lws2_32'
              ]
            }
          }]
        ]
      }]
    ]
  }]
}
