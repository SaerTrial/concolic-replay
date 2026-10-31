if not fs.is_file(meson.project_source_root() / 'hooks/arm/function_hooks.c')
  error('Missing firmware hooks. Run: git submodule update --init hooks')
endif

specific_ss.add(when: ['CONFIG_CONCOLIC_MACHINE', 'TARGET_ARM'], if_true: files(
  'utils/mem.c',
  'configurable_machine.c',
  '../../hooks/arm/function_hooks.c',
  'arm/hook_backend.c',
  'arm/interrupt_firing.c'
))
