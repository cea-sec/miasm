int test(unsigned int argc, char** argv)
{
	unsigned int ret;
	if (argc == 0)
		ret = 0x1001;
	else if (argc < 2)
		ret = 0x1002;
	else if (argc <= 5)
		ret = 0x1003;
	else if (argc != 7 && argc*2 == 14)
		ret = 0x1004;
	else if (argc*2 == 14)
		ret = 0x1005;
	else if (argc & 0x30)
		ret = 0x1006;
	else if (argc + 3 == 0x45)
		ret = 0x1007;
	else
		ret = 0x1008;
	return ret;
}

int main(int argc, char** argv)
{
	return test(argc, argv);
}
