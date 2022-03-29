project(
    'libespi',
    'cpp',
    license: 'Apache-2.0',
    version: '1.0',
    meson_version: '>=0.57.0',
    default_options: [
        'warning_level=2',
        'werror=true',
        'cpp_std=c++17'
    ]
)

add_project_arguments(
      '-Wno-implicit-fallthrough',
        language: 'cpp',
)

cpp = meson.get_compiler('cpp')
dep_pthread = cpp.find_library('pthread', required : true)

libespi_src_files = ['src/espi_channel.cpp',
                     'src/espi_oob_channel.cpp']
libespi_inc_dir= include_directories('include')

libespi = shared_library('espi',
                         libespi_src_files,
                         include_directories : libespi_inc_dir,
                         install : true,
                         version: meson.project_version())

espi_cmd_src_files = ['src/espi_cmd.cpp']
espi_cmd_bin = executable('espi_cmd',
                          sources: espi_cmd_src_files,
                          install : true,
                          include_directories : libespi_inc_dir,
                          link_with: [libespi],
                          dependencies: [dep_pthread]
                          )

