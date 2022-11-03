/* ProgressBar Class Implementation */

/* ================================== INCLUDES ================================== */
#include "ProgressBar.h"


/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

ProgressBar::ProgressBar() :
  progress(0),
  n_cycles(0),
  last_perc(0),
  do_show_bar(true),
  update_is_called(false),
  done_char("█"),
  todo_char(" "),
  opening_bracket_char("["),
  closing_bracket_char("]"),
  output(std::cout) {}

ProgressBar::ProgressBar(int n, bool showbar, std::ostream& out) :
  progress(0),
  n_cycles(n),
  last_perc(0),
  do_show_bar(showbar),
  update_is_called(false),
  done_char("█"),
  todo_char(" "),
  opening_bracket_char("["),
  closing_bracket_char("]"),
  output(out) {}


/* ============================= OTHER PUBLIC METHODS ============================= */

void ProgressBar::reset()
 {
  progress = 0,
  update_is_called = false;
  last_perc = 0;
 }

__attribute__((unused)) void ProgressBar::set_niter(int niter)
 {
  if (niter <= 0)
   throw std::invalid_argument("ProgressBar::set_niter: number of iterations null or negative");
  n_cycles = niter;
 }

void ProgressBar::update()
{
 if(n_cycles == 0)
  throw std::runtime_error("ProgressBar::update: number of cycles not set");

 if(!update_is_called)
  {
   if(do_show_bar)
    {
     output << opening_bracket_char;
     for (int _ = 0; _ < 50; _++)
      output << todo_char;
     output << closing_bracket_char << " 0%";
    }
   else
    output << "0%";
  }
 update_is_called = true;

 int perc;

 // compute percentage, if did not change, do nothing and return
 perc = (int)(progress*100./(n_cycles-1));
 if(perc < last_perc)
  return;

 // update percentage each unit
 if (perc == last_perc + 1)
  {
   // erase the correct  number of characters
   if(perc <= 10)
    output << "\b\b"   << perc << '%';
   else
    if(perc <= 100)
     output << "\b\b\b" << perc << '%';
  }
 if(do_show_bar)
  {
   // update bar every ten units
   if (perc % 2 == 0)
    {
     // erase closing bracket
     output << std::string(closing_bracket_char.size(), '\b');

     // erase trailing percentage characters
     if(perc  < 10)
      output << "\b\b\b";
     else
      if(perc < 100)
       output << "\b\b\b\b";
      else
       if(perc == 100)
        output << "\b\b\b\b\b";

     // erase 'todo_char'
     for(int j = 0; j < 50-(perc-1)/2; ++j)
      output << std::string(todo_char.size(), '\b');


     // add one additional 'done_char'
     if(perc == 0)
      output << todo_char;
     else
      output << done_char;

     // refill with 'todo_char'
     for(int j = 0; j < 50-(perc-1)/2-1; ++j)
      output << todo_char;

     // read trailing percentage characters
     output << closing_bracket_char << ' ' << perc << '%';
    }
   }
  last_perc = perc;
  ++progress;
  output << std::flush;
 }