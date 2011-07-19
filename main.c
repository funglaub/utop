#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/types.h>

#include "proc.h"
#include "gui.h"

#define MS_TO_US(n) ((n) * 1000)

int main(void)
{
	static struct proc **proclist;

	gui_init();

	proclist = proc_init();

	gui_run(proclist);

	gui_term();

	return 0;
}
