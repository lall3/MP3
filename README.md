MP2 doccumentation


Run code by running the following

Make
sudo insmod lall3_mp2.ko
./userapp 1000


Design:
I expanded the strict used in mp1 by adding proc_time, linux_task, list_head strictures.

I built the MP around my list names process_list.
As task the added they are added to this list, and they are removed from the list whist de-registering.

The most challenging pst of my Mp was a paging bug I encountered while trying to yield. This was because of incorrect registration. I fixed the bug by changing the way new processes were added to the list.

As for the timer_handler that behaves as the top half, I used something very similar to what was in Mp1. I wake up the dispatcher thread at the end. This is the bottom half of our interrupt handler.

I used 2 functions to deal with the top half. On invokes the helper function that finds a task to schedule and uses linux api to schedule the new task that is found.

My mod still has a null pointer error whilst changing between tasks. I was unable to fix it.


