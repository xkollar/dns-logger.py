#!/bin/bash

SERVICE="/root/dns_logger.py"

PID=""

function get_pid {
   PID=`pidof python $SERVICE`
}

function stop {
   get_pid
   if [ -z $PID ]; then
      echo "server is not running."
      exit 1
   else
      echo -n "Stopping server.."
      kill -SIGINT $PID
      sleep 1
      echo ".. Done."
   fi
}

function start {
   get_pid
   if [ -z $PID ]; then
      echo  "Starting server.."
      python $SERVICE &
      get_pid
      echo "Done. PID=$PID"
   else
      echo "server is already running, PID=$PID"
   fi
}

function restart {
   echo  "Restarting server.."
   get_pid
   if [ -z $PID ]; then
      start
   else
      stop
      sleep 5
      start
  fi
}

function status {
   get_pid
   if [ -z  $PID ]; then
      echo "Server is not running."
      exit 1
   else
      echo "Server is running, PID=$PID"
   fi
}

case "$1" in
   start)
      start
   ;;
   stop)
      stop
   ;;
   restart)
      restart
   ;;
   status)
      status
   ;;
   *)
      echo "Usage: $0 {start|stop|restart|status}"
esac
