{
  'targets': [
    {
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
        'MACOSX_DEPLOYMENT_TARGET': '10.7',
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
      ],
    }
  ]
}