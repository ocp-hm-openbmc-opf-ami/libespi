project(
    'libespi',
    'cpp',
    license: 'Apache-2.0',
    version: '0.1',
    meson_version: '>=0.57.0',
    default_options: [
        'warning_level=2',
        'werror=true',
]
)

add_project_arguments(
        '-Wcast-align',
        '-Wconversion',
        '-Wsign-conversion',
        '-Wnull-dereference',
        '-Wdouble-promotion',
        '-Wformat=2',
        '-Wno-unused-parameter',
        '-Wduplicated-cond',
        '-Wduplicated-branches',
        '-Wlogical-op',
        language: 'cpp',
)

cpp = meson.get_compiler('cpp')
dep_pthread = cpp.find_library('pthread', required : true)

src_files = ['src/espi_channel.cpp']
inc = include_directories('include')

libespi = shared_library('espi',
                        src_files,
                        include_directories : inc,
                        install : true,
                        version: meson.project_version())

my_dep = declare_dependency(link_with: libespi, include_directories: inc)

espi_cmd_src = ['src/espi_cmd.cpp']
espi_cmd_bin = executable('espi_cmd',
                          sources: espi_cmd_src,
                          install : true,
                          include_directories : inc,
                          link_with: [libespi],
                          dependencies: [dep_pthread]
                          )
