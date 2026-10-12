# A line in reporter.log as soon as Zeek is up. Reading a fifo does not
# end, so connection logs wait for traffic; this does not.
event zeek_init()
	{
	Reporter::info("werewolf-zeek");
	}
