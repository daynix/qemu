qmp_ss.add(files('monitor.c', 'qmp.c', 'qmp-cmds-control.c'))

softmmu_ss.add(files(
  'hmp-cmds.c',
  'hmp.c',
))
softmmu_ss.add([spice_headers, files('qmp-cmds.c')])
softmmu_ss.add(files('qemu-helper-stamp-utils.c'))

specific_ss.add(when: 'CONFIG_SOFTMMU', if_true: [files('misc.c'), spice])
