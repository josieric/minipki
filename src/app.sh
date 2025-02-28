#! /bin/bash

ACTIVATEENV=". /opt/mamba/bin/activate base"
BINDHOST=localhost
URLPREFIX="/pki"
PORT=5001

APPDIR=app
APPNAME="$APPDIR:app"

cd `dirname $0`
APPLOG=log
[ ! -d "$APPLOG" ] && mkdir -p $APPLOG

COLORED="\e[96m"
NORMAL="\e[0m"

PIDFILE=$APPLOG/pid.log

mikill() {
  MIFILE=$1
  SIGNAL=$2
  [ -z "$SIGNAL" ] && SIGNAL=SIGTERM
  [ ! -f $MIFILE ] && echo "No pid file" && exit 12
  PID=`cat $MIFILE`
  if [ -z "$PID" ]; then
    echo "No pid in file $MIFILE"
    exit 12
  fi
  echo "kill -$SIGNAL $PID"
  kill -$SIGNAL $PID
}

case "$1" in
"reload") mikill $PIDFILE SIGHUP
  ;;

"stop")
    mikill $PIDFILE
    # wait 1 second and is done ?
    sleep 1
    ps -ef | grep -v grep | grep $PID | while read msg
    do
      echo -e "${COLORED}Process already exists: $NORMAL$msg"
    done
  ;;

"start")
  if [ ! -f $APPDIR/server.key -a ! -f $APPDIR/server.crt ] ;then
     openssl req -x509 -newkey rsa:4096 -nodes -keyout $APPDIR/server.key -out $APPDIR/server.crt -days 365 -subj "/CN=`hostname`/O=QuickAutoSigned/C=FR"
  fi
  SSLOPTION="--keyfile $APPDIR/server.key --certfile $APPDIR/server.crt"
  $ACTIVATEENV
  gunicorn --bind $BINDHOST:$PORT \
         --workers 3 \
         --max-requests 128 \
         --worker-connections 128 \
         --worker-tmp-dir $APPLOG \
         --log-level=info \
         --pid $APPLOG/pid.log \
	 --reload \
	 --daemon \
         --error-logfile $APPLOG/error.log \
         --access-logfile $APPLOG/access.log \
         --access-logformat '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"' \
	 --env "SCRIPT_NAME=$URLPREFIX" \
         $SSLOPTION \
    $APPNAME
  ;;

*)
  echo -e "${COLORED}Usage:$NORMAL $0 <start|stop|reload>"
  ;;
esac

