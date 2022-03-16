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

c = meson.get_compiler('cpp')
src_files = ['src/espi_channel.cpp']
inc = include_directories('include')

libespi = shared_library('libespi',
                        src_files,
                        include_directories : inc,
                        install : true)

