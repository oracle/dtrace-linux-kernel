# SPDX-License-Identifier: GPL-2.0
# ==========================================================================
# Generating check-tristates.objs
# ==========================================================================

src := $(obj)

PHONY := __tristates
__tristates:

include include/config/auto.conf
# tristate.conf sets tristate variables to uppercase 'Y' or 'M'
# That way, we get the list of built-in modules in obj-Y
include include/config/tristate.conf

include scripts/Kbuild.include

ifdef building_out_of_srctree
# Create output directory if not already present
_dummy := $(shell [ -d $(obj) ] || mkdir -p $(obj))
endif

# The filename Kbuild has precedence over Makefile
kbuild-dir := $(if $(filter /%,$(src)),$(src),$(srctree)/$(src))
kbuild-file := $(if $(wildcard $(kbuild-dir)/Kbuild),$(kbuild-dir)/Kbuild,$(kbuild-dir)/Makefile)
include $(kbuild-file)

include scripts/Makefile.lib

check-tristates-subdirs := $(patsubst %,%/check-tristates.objs, $(subdir-ym))
check-tristates-target  := $(obj)/check-tristates.objs

__tristates: $(obj)/$(tristates-file) $(subdir-ym)
	@:

$(check-tristates-target): $(subdir-ym) FORCE
	$(Q) rm -f $@
	$(Q) $(foreach mod-o, $(filter %.o,$(obj-Y)),\
		printf "%s: " $(addprefix $(obj)/,$(mod-o)) >> $@; \
		printf " %s" $(sort $(strip $(addprefix $(obj)/,$($(mod-o:.o=-objs)) \
			$($(mod-o:.o=-y)) $($(mod-o:.o=-Y))))) >> $@; \
		printf "\n" >> $@; ) \
	cat /dev/null $(check-tristates-subdirs) >> $@;

PHONY += FORCE

FORCE:

# Descending
# ---------------------------------------------------------------------------

PHONY += $(subdir-ym)
$(subdir-ym):
	$(Q)$(MAKE) $(tristatecheck)=$@ tristates-file=$(tristates-file)

.PHONY: $(PHONY)
