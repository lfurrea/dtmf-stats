PROJECT = dtmf_stats
PROJECT_DESCRIPTION = DTMF stats out of pcap capture
PROJECT_VERSION = 0.0.1
DEPS = lager
dep_lager = git https://github.com/basho/lager.git 3.1.0
include erlang.mk

# Compile flags
ERLC_COMPILE_OPTS= +'{parse_transform, lager_transform}'

# Append these settings
ERLC_OPTS += $(ERLC_COMPILE_OPTS)
TEST_ERLC_OPTS += $(ERLC_COMPILE_OPTS)
