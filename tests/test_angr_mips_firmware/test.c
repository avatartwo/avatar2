
int fun(char *input)
{
  int res = 0;
  int i = input[0];
  if (0 <= i && i < 10 && i * i == 25) {
    res = 1;
  }
  return res;
}

void main(void)
{
  char buf[4] = {0};
  fun(buf);
  while(1);
}

