specific_ss.add(when: ['CONFIG_AVATAR', 'TARGET_ARM'], if_true: files(
  'configurable_machine.c',
  'avatar_posix.c',
  'remote_memory.c',
  'arm_helper.c'
))
specific_ss.add(when: ['CONFIG_AVATAR', 'TARGET_AARCH64'], if_true: files(
  'configurable_machine.c',
  'avatar_posix.c',
  'remote_memory.c',
  'arm_helper.c'
))
specific_ss.add(when: ['CONFIG_AVATAR', 'CONFIG_ARM_V7M'], if_true: files('interrupts.c'))

specific_ss.add(when: ['CONFIG_AVATAR', 'TARGET_MIPS'], if_true: files(
  'configurable_machine.c',
  'avatar_posix.c',
  'remote_memory.c'
))
specific_ss.add(when: ['CONFIG_AVATAR', 'TARGET_I386'], if_true: files('configurable_machine.c'))
specific_ss.add(when: ['CONFIG_AVATAR', 'TARGET_X86_64'], if_true: files('configurable_machine.c'))
specific_ss.add(when: ['CONFIG_AVATAR', 'TARGET_PPC'], if_true: files('configurable_machine.c'))

specific_ss.add(when: ['CONFIG_AVATAR', 'TARGET_AVR'], if_true: files(
  'configurable_machine.c',
  'avatar_posix.c',
  'remote_memory.c',
))
