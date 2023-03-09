#include <seelib.h>

int rust_main(void);

int main(void)
{
  SEElib_init();
  return rust_main();
}
