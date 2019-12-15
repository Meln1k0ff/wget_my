#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int file_size(const char *filename)
{
  int size;
  FILE *fp = fopen (filename, "rb");
  if (!fp)
    return -1;
  fseeko (fp, 0, SEEK_END);
  size = ftello (fp);
  fclose (fp);
  return size;
}

char *
strdupdelim (const char *beg, const char *end)
{
  if (beg && beg <= end)
    {
      char *res = malloc (end - beg + 1);
      memcpy (res, beg, end - beg);
      res[end - beg] = '\0';
      return res;
    }

  return strdup("");
}
