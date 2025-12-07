specific_ss.add(when: ['CONFIG_CONCOLIC_MACHINE', 'TARGET_ARM'], if_true: files(
  'utils/mem.c',
  'configurable_machine.c',
  'arm/function_hooks.c',
  'arm/interrupt_firing.c'
))