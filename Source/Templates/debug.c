
# ifdef hc_DEBUG
# include <stdio.h>
# define hc_dbg(msg, ...) printf("[DEBUG]::Hashycalls.%s.L%d -> " msg "\n", __func__, __LINE__, ##__VA_ARGS__)
# endif

# ifndef hc_DEBUG
# define hc_dbg(msg, ...) do {} while (0)
# endif
