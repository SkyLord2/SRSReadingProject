//
// Copyright (c) 2013-2021 The SRS Authors
//
// SPDX-License-Identifier: MIT or MulanPSL-2.0
//

#include <srs_app_server.hpp>

#include <sys/types.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#ifndef SRS_OSX
#include <sys/inotify.h>
#endif
using namespace std;

#include <srs_kernel_log.hpp>
#include <srs_kernel_error.hpp>
#include <srs_app_rtmp_conn.hpp>
#include <srs_app_config.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_app_http_api.hpp>
#include <srs_app_http_conn.hpp>
#include <srs_app_ingest.hpp>
#include <srs_app_source.hpp>
#include <srs_app_utility.hpp>
#include <srs_app_heartbeat.hpp>
#include <srs_app_mpegts_udp.hpp>
#include <srs_app_statistic.hpp>
#include <srs_app_caster_flv.hpp>
#include <srs_kernel_consts.hpp>
#include <srs_app_coworkers.hpp>
#include <srs_service_log.hpp>
#include <srs_app_latest_version.hpp>

std::string srs_listener_type2string(SrsListenerType type)
{
    switch (type) {
        case SrsListenerRtmpStream:
            return "RTMP";
        case SrsListenerHttpApi:
            return "HTTP-API";
        case SrsListenerHttpsApi:
            return "HTTPS-API";
        case SrsListenerHttpStream:
            return "HTTP-Server";
        case SrsListenerHttpsStream:
            return "HTTPS-Server";
        case SrsListenerMpegTsOverUdp:
            return "MPEG-TS over UDP";
        case SrsListenerFlv:
            return "HTTP-FLV";
        default:
            return "UNKONWN";
    }
}

SrsListener::SrsListener(SrsServer* svr, SrsListenerType t)
{
    port = 0;
    server = svr;
    type = t;
}

SrsListener::~SrsListener()
{
}

SrsListenerType SrsListener::listen_type()
{
    return type;
}

SrsBufferListener::SrsBufferListener(SrsServer* svr, SrsListenerType t) : SrsListener(svr, t)
{
    listener = NULL;
}

SrsBufferListener::~SrsBufferListener()
{
    srs_freep(listener);
}

srs_error_t SrsBufferListener::listen(string i, int p)
{
    srs_error_t err = srs_success;
    
    ip = i;
    port = p;
    
    srs_freep(listener);
    // ����һ��TCP����
    listener = new SrsTcpListener(this, ip, port);
    
    if ((err = listener->listen()) != srs_success) {
        return srs_error_wrap(err, "buffered tcp listen");
    }
    
    string v = srs_listener_type2string(type);
    srs_trace("%s listen at tcp://%s:%d, fd=%d", v.c_str(), ip.c_str(), port, listener->fd());
    
    return err;
}

srs_error_t SrsBufferListener::on_tcp_client(srs_netfd_t stfd)
{
    // �յ�TCP����֮����� SrsServer::accept_client ���д��� 
    srs_error_t err = server->accept_client(type, stfd);
    if (err != srs_success) {
        srs_warn("accept client failed, err is %s", srs_error_desc(err).c_str());
        srs_freep(err);
    }
    
    return srs_success;
}

SrsHttpFlvListener::SrsHttpFlvListener(SrsServer* svr, SrsListenerType t, SrsConfDirective* c) : SrsListener(svr, t)
{
    listener = NULL;
    
    // the caller already ensure the type is ok,
    // we just assert here for unknown stream caster.
    srs_assert(type == SrsListenerFlv);
    if (type == SrsListenerFlv) {
        caster = new SrsAppCasterFlv(c);
    }
}

SrsHttpFlvListener::~SrsHttpFlvListener()
{
    srs_freep(caster);
    srs_freep(listener);
}

srs_error_t SrsHttpFlvListener::listen(string i, int p)
{
    srs_error_t err = srs_success;
    
    // the caller already ensure the type is ok,
    // we just assert here for unknown stream caster.
    srs_assert(type == SrsListenerFlv);
    
    ip = i;
    port = p;
    
    if ((err = caster->initialize()) != srs_success) {
        return srs_error_wrap(err, "init caster %s:%d", ip.c_str(), port);
    }
    
    srs_freep(listener);
    listener = new SrsTcpListener(this, ip, port);
    
    if ((err = listener->listen()) != srs_success) {
        return srs_error_wrap(err, "listen");
    }
    
    string v = srs_listener_type2string(type);
    srs_trace("%s listen at tcp://%s:%d, fd=%d", v.c_str(), ip.c_str(), port, listener->fd());
    
    return err;
}

srs_error_t SrsHttpFlvListener::on_tcp_client(srs_netfd_t stfd)
{
    srs_error_t err = caster->on_tcp_client(stfd);
    if (err != srs_success) {
        srs_warn("accept client failed, err is %s", srs_error_desc(err).c_str());
        srs_freep(err);
    }
    
    return err;
}

SrsUdpStreamListener::SrsUdpStreamListener(SrsServer* svr, SrsListenerType t, ISrsUdpHandler* c) : SrsListener(svr, t)
{
    listener = NULL;
    caster = c;
}

SrsUdpStreamListener::~SrsUdpStreamListener()
{
    srs_freep(listener);
}

srs_error_t SrsUdpStreamListener::listen(string i, int p)
{
    srs_error_t err = srs_success;
    
    // the caller already ensure the type is ok,
    // we just assert here for unknown stream caster.
    srs_assert(type == SrsListenerMpegTsOverUdp);
    
    ip = i;
    port = p;
    
    srs_freep(listener);
    listener = new SrsUdpListener(caster, ip, port);
    
    if ((err = listener->listen()) != srs_success) {
        return srs_error_wrap(err, "listen %s:%d", ip.c_str(), port);
    }
    
    // notify the handler the fd changed.
    if ((err = caster->on_stfd_change(listener->stfd())) != srs_success) {
        return srs_error_wrap(err, "notify fd change failed");
    }
    
    string v = srs_listener_type2string(type);
    srs_trace("%s listen at udp://%s:%d, fd=%d", v.c_str(), ip.c_str(), port, listener->fd());
    
    return err;
}

SrsUdpCasterListener::SrsUdpCasterListener(SrsServer* svr, SrsListenerType t, SrsConfDirective* c) : SrsUdpStreamListener(svr, t, NULL)
{
    // the caller already ensure the type is ok,
    // we just assert here for unknown stream caster.
    srs_assert(type == SrsListenerMpegTsOverUdp);
    if (type == SrsListenerMpegTsOverUdp) {
        caster = new SrsMpegtsOverUdp(c);
    }
}

SrsUdpCasterListener::~SrsUdpCasterListener()
{
    srs_freep(caster);
}

SrsSignalManager* SrsSignalManager::instance = NULL;

SrsSignalManager::SrsSignalManager(SrsServer* s)
{
    SrsSignalManager::instance = this;
    
    server = s;
    sig_pipe[0] = sig_pipe[1] = -1;
    trd = new SrsSTCoroutine("signal", this, _srs_context->get_id());
    signal_read_stfd = NULL;
}

SrsSignalManager::~SrsSignalManager()
{
    srs_freep(trd);

    srs_close_stfd(signal_read_stfd);
    
    if (sig_pipe[0] > 0) {
        ::close(sig_pipe[0]);
    }
    if (sig_pipe[1] > 0) {
        ::close(sig_pipe[1]);
    }
}

srs_error_t SrsSignalManager::initialize()
{
    /* Create signal pipe */
    if (pipe(sig_pipe) < 0) {
        return srs_error_new(ERROR_SYSTEM_CREATE_PIPE, "create pipe");
    }
    
    if ((signal_read_stfd = srs_netfd_open(sig_pipe[0])) == NULL) {
        return srs_error_new(ERROR_SYSTEM_CREATE_PIPE, "open pipe");
    }
    
    return srs_success;
}

srs_error_t SrsSignalManager::start()
{
    srs_error_t err = srs_success;
    
    /**
     * Note that if multiple processes are used (see below),
     * the signal pipe should be initialized after the fork(2) call
     * so that each process has its own private pipe.
     */
    struct sigaction sa;
    
    /* Install sig_catcher() as a signal handler */
    sa.sa_handler = SrsSignalManager::sig_catcher;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SRS_SIGNAL_RELOAD, &sa, NULL);
    
    sa.sa_handler = SrsSignalManager::sig_catcher;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SRS_SIGNAL_FAST_QUIT, &sa, NULL);

    sa.sa_handler = SrsSignalManager::sig_catcher;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SRS_SIGNAL_GRACEFULLY_QUIT, &sa, NULL);
    
    sa.sa_handler = SrsSignalManager::sig_catcher;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    
    sa.sa_handler = SrsSignalManager::sig_catcher;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SRS_SIGNAL_REOPEN_LOG, &sa, NULL);
    
    srs_trace("signal installed, reload=%d, reopen=%d, fast_quit=%d, grace_quit=%d",
              SRS_SIGNAL_RELOAD, SRS_SIGNAL_REOPEN_LOG, SRS_SIGNAL_FAST_QUIT, SRS_SIGNAL_GRACEFULLY_QUIT);
    
    if ((err = trd->start()) != srs_success) {
        return srs_error_wrap(err, "signal manager");
    }
    
    return err;
}

srs_error_t SrsSignalManager::cycle()
{
    srs_error_t err = srs_success;
    
    while (true) {
        if ((err = trd->pull()) != srs_success) {
            return srs_error_wrap(err, "signal manager");
        }
        
        int signo;
        
        /* Read the next signal from the pipe */
        srs_read(signal_read_stfd, &signo, sizeof(int), SRS_UTIME_NO_TIMEOUT);
        
        /* Process signal synchronously */
        server->on_signal(signo);
    }
    
    return err;
}

void SrsSignalManager::sig_catcher(int signo)
{
    int err;
    
    /* Save errno to restore it after the write() */
    err = errno;
    
    /* write() is reentrant/async-safe */
    int fd = SrsSignalManager::instance->sig_pipe[1];
    write(fd, &signo, sizeof(int));
    
    errno = err;
}

// Whether we are in docker, defined in main module.
extern bool _srs_in_docker;

SrsInotifyWorker::SrsInotifyWorker(SrsServer* s)
{
    server = s;
    trd = new SrsSTCoroutine("inotify", this);
    inotify_fd = NULL;
}

SrsInotifyWorker::~SrsInotifyWorker()
{
    srs_freep(trd);
    srs_close_stfd(inotify_fd);
}

srs_error_t SrsInotifyWorker::start()
{
    srs_error_t err = srs_success;

#ifndef SRS_OSX
    // Whether enable auto reload config.
    bool auto_reload = _srs_config->inotify_auto_reload();
    if (!auto_reload && _srs_in_docker && _srs_config->auto_reload_for_docker()) {
        srs_warn("enable auto reload for docker");
        auto_reload = true;
    }

    if (!auto_reload) {
        return err;
    }

    // Create inotify to watch config file.
    int fd = ::inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        return srs_error_new(ERROR_INOTIFY_CREATE, "create inotify");
    }

    // Open as stfd to read by ST.
    if ((inotify_fd = srs_netfd_open(fd)) == NULL) {
        ::close(fd);
        return srs_error_new(ERROR_INOTIFY_OPENFD, "open fd=%d", fd);
    }

    if (((err = srs_fd_closeexec(fd))) != srs_success) {
        return srs_error_wrap(err, "closeexec fd=%d", fd);
    }

    // /* the following are legal, implemented events that user-space can watch for */
    // #define IN_ACCESS               0x00000001      /* File was accessed */
    // #define IN_MODIFY               0x00000002      /* File was modified */
    // #define IN_ATTRIB               0x00000004      /* Metadata changed */
    // #define IN_CLOSE_WRITE          0x00000008      /* Writtable file was closed */
    // #define IN_CLOSE_NOWRITE        0x00000010      /* Unwrittable file closed */
    // #define IN_OPEN                 0x00000020      /* File was opened */
    // #define IN_MOVED_FROM           0x00000040      /* File was moved from X */
    // #define IN_MOVED_TO             0x00000080      /* File was moved to Y */
    // #define IN_CREATE               0x00000100      /* Subfile was created */
    // #define IN_DELETE               0x00000200      /* Subfile was deleted */
    // #define IN_DELETE_SELF          0x00000400      /* Self was deleted */
    // #define IN_MOVE_SELF            0x00000800      /* Self was moved */
    //
    // /* the following are legal events.  they are sent as needed to any watch */
    // #define IN_UNMOUNT              0x00002000      /* Backing fs was unmounted */
    // #define IN_Q_OVERFLOW           0x00004000      /* Event queued overflowed */
    // #define IN_IGNORED              0x00008000      /* File was ignored */
    //
    // /* helper events */
    // #define IN_CLOSE                (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE) /* close */
    // #define IN_MOVE                 (IN_MOVED_FROM | IN_MOVED_TO) /* moves */
    //
    // /* special flags */
    // #define IN_ONLYDIR              0x01000000      /* only watch the path if it is a directory */
    // #define IN_DONT_FOLLOW          0x02000000      /* don't follow a sym link */
    // #define IN_EXCL_UNLINK          0x04000000      /* exclude events on unlinked objects */
    // #define IN_MASK_ADD             0x20000000      /* add to the mask of an already existing watch */
    // #define IN_ISDIR                0x40000000      /* event occurred against dir */
    // #define IN_ONESHOT              0x80000000      /* only send event once */

    // Watch the config directory events.
    string config_dir = srs_path_dirname(_srs_config->config());
    uint32_t mask = IN_MODIFY | IN_CREATE | IN_MOVED_TO; int watch_conf = 0;
    if ((watch_conf = ::inotify_add_watch(fd, config_dir.c_str(), mask)) < 0) {
        return srs_error_new(ERROR_INOTIFY_WATCH, "watch file=%s, fd=%d, watch=%d, mask=%#x",
            config_dir.c_str(), fd, watch_conf, mask);
    }
    srs_trace("auto reload watching fd=%d, watch=%d, file=%s", fd, watch_conf, config_dir.c_str());

    if ((err = trd->start()) != srs_success) {
        return srs_error_wrap(err, "inotify");
    }
#endif

    return err;
}

srs_error_t SrsInotifyWorker::cycle()
{
    srs_error_t err = srs_success;

#ifndef SRS_OSX
    string config_path = _srs_config->config();
    string config_file = srs_path_basename(config_path);
    string k8s_file = "..data";

    while (true) {
        char buf[4096];
        ssize_t nn = srs_read(inotify_fd, buf, (size_t)sizeof(buf), SRS_UTIME_NO_TIMEOUT);
        if (nn < 0) {
            srs_warn("inotify ignore read failed, nn=%d", (int)nn);
            break;
        }

        // Whether config file changed.
        bool do_reload = false;

        // Parse all inotify events.
        inotify_event* ie = NULL;
        for (char* ptr = buf; ptr < buf + nn; ptr += sizeof(inotify_event) + ie->len) {
            ie = (inotify_event*)ptr;

            if (!ie->len || !ie->name) {
                continue;
            }

            string name = ie->name;
            if ((name == k8s_file || name == config_file) && ie->mask & (IN_MODIFY|IN_CREATE|IN_MOVED_TO)) {
                do_reload = true;
            }

            srs_trace("inotify event wd=%d, mask=%#x, len=%d, name=%s, reload=%d", ie->wd, ie->mask, ie->len, ie->name, do_reload);
        }

        // Notify server to do reload.
        if (do_reload && srs_path_exists(config_path)) {
            server->on_signal(SRS_SIGNAL_RELOAD);
        }

        srs_usleep(3000 * SRS_UTIME_MILLISECONDS);
    }
#endif

    return err;
}

ISrsServerCycle::ISrsServerCycle()
{
}

ISrsServerCycle::~ISrsServerCycle()
{
}

SrsServer::SrsServer()
{
    signal_reload = false;
    signal_persistence_config = false;
    signal_gmc_stop = false;
    signal_fast_quit = false;
    signal_gracefully_quit = false;
    pid_fd = -1;
    
    signal_manager = new SrsSignalManager(this);
    conn_manager = new SrsResourceManager("TCP", true);
    latest_version_ = new SrsLatestVersion();

    handler = NULL;
    ppid = ::getppid();
    
    // donot new object in constructor,
    // for some global instance is not ready now,
    // new these objects in initialize instead.
    http_api_mux = new SrsHttpServeMux();
    http_server = new SrsHttpServer(this);
    http_heartbeat = new SrsHttpHeartbeat();
    ingester = new SrsIngester();
    trd_ = new SrsSTCoroutine("srs", this, _srs_context->get_id());
    timer_ = NULL;
    wg_ = NULL;
}

SrsServer::~SrsServer()
{
    destroy();
}

void SrsServer::destroy()
{
    srs_warn("start destroy server");

    srs_freep(trd_);
    srs_freep(timer_);

    dispose();
    
    srs_freep(http_api_mux);
    srs_freep(http_server);
    srs_freep(http_heartbeat);
    srs_freep(ingester);
    
    if (pid_fd > 0) {
        ::close(pid_fd);
        pid_fd = -1;
    }
    
    srs_freep(signal_manager);
    srs_freep(latest_version_);
    srs_freep(conn_manager);
}

void SrsServer::dispose()
{
    _srs_config->unsubscribe(this);
    
    // prevent fresh clients.
    close_listeners(SrsListenerRtmpStream);
    close_listeners(SrsListenerHttpApi);
    close_listeners(SrsListenerHttpsApi);
    close_listeners(SrsListenerHttpStream);
    close_listeners(SrsListenerHttpsStream);
    close_listeners(SrsListenerMpegTsOverUdp);
    close_listeners(SrsListenerFlv);
    
    // Fast stop to notify FFMPEG to quit, wait for a while then fast kill.
    ingester->dispose();
    
    // dispose the source for hls and dvr.
    _srs_sources->dispose();
    
    // @remark don't dispose all connections, for too slow.
}

void SrsServer::gracefully_dispose()
{
    _srs_config->unsubscribe(this);

    // Always wait for a while to start.
    srs_usleep(_srs_config->get_grace_start_wait());
    srs_trace("start wait for %dms", srsu2msi(_srs_config->get_grace_start_wait()));

    // prevent fresh clients.
    close_listeners(SrsListenerRtmpStream);
    close_listeners(SrsListenerHttpApi);
    close_listeners(SrsListenerHttpsApi);
    close_listeners(SrsListenerHttpStream);
    close_listeners(SrsListenerHttpsStream);
    close_listeners(SrsListenerMpegTsOverUdp);
    close_listeners(SrsListenerFlv);
    srs_trace("listeners closed");

    // Fast stop to notify FFMPEG to quit, wait for a while then fast kill.
    ingester->stop();
    srs_trace("ingesters stopped");

    // Wait for connections to quit.
    // While gracefully quiting, user can requires SRS to fast quit.
    int wait_step = 1;
    while (!conn_manager->empty() && !signal_fast_quit) {
        for (int i = 0; i < wait_step && !conn_manager->empty() && !signal_fast_quit; i++) {
            srs_usleep(1000 * SRS_UTIME_MILLISECONDS);
        }

        wait_step = (wait_step * 2) % 33;
        srs_trace("wait for %d conns to quit", (int)conn_manager->size());
    }

    // dispose the source for hls and dvr.
    _srs_sources->dispose();
    srs_trace("source disposed");

    srs_usleep(_srs_config->get_grace_final_wait());
    srs_trace("final wait for %dms", srsu2msi(_srs_config->get_grace_final_wait()));
}

srs_error_t SrsServer::initialize(ISrsServerCycle* ch)
{
    srs_error_t err = srs_success;
    
    // for the main objects(server, config, log, context),
    // never subscribe handler in constructor,
    // instead, subscribe handler in initialize method.
    srs_assert(_srs_config);
    // ע�������ļ��ȼ���ʱ�Ļص�����
    _srs_config->subscribe(this);
    
    handler = ch;
    if(handler && (err = handler->initialize()) != srs_success){
        return srs_error_wrap(err, "handler initialize");
    }
    // http �������, ������ƥ���handler
    if ((err = http_api_mux->initialize()) != srs_success) {
        return srs_error_wrap(err, "http api initialize");
    }
    // �ṩ http flv ������, �Լ�http��̬��Դ����
    if ((err = http_server->initialize()) != srs_success) {
        return srs_error_wrap(err, "http server initialize");
    }
    
    return err;
}

srs_error_t SrsServer::initialize_st()
{
    srs_error_t err = srs_success;

    // check asprocess.
    bool asprocess = _srs_config->get_asprocess();
    if (asprocess && ppid == 1) {
        return srs_error_new(ERROR_SYSTEM_ASSERT_FAILED, "ppid=%d illegal for asprocess", ppid);
    }
    
    srs_trace("server main cid=%s, pid=%d, ppid=%d, asprocess=%d",
        _srs_context->get_id().c_str(), ::getpid(), ppid, asprocess);
    
    return err;
}

srs_error_t SrsServer::initialize_signal()
{
    srs_error_t err = srs_success;

    if ((err = signal_manager->initialize()) != srs_success) {
        return srs_error_wrap(err, "init signal manager");
    }

    // Start the version query coroutine.
    if ((err = latest_version_->start()) != srs_success) {
        return srs_error_wrap(err, "start version query");
    }

    return err;
}

srs_error_t SrsServer::acquire_pid_file()
{
    srs_error_t err = srs_success;

    // when srs in dolphin mode, no need the pid file.
    // �����ģʽ
    if (_srs_config->is_dolphin()) {
        return srs_success;
    }
    
    std::string pid_file = _srs_config->get_pid_file();

    // Try to create dir for pid file.
    string pid_dir = srs_path_dirname(pid_file);
    if (!srs_path_exists(pid_dir)) {
        if ((err = srs_create_dir_recursively(pid_dir)) != srs_success) {
            return srs_error_wrap(err, "create %s", pid_dir.c_str());
        }
    }
    
    // -rw-r--r--
    // 644
    int mode = S_IRUSR | S_IWUSR |  S_IRGRP | S_IROTH;
    
    int fd;
    // open pid file
    if ((fd = ::open(pid_file.c_str(), O_WRONLY | O_CREAT, mode)) == -1) {
        return srs_error_new(ERROR_SYSTEM_PID_ACQUIRE, "open pid file=%s", pid_file.c_str());
    }
    
    // require write lock
    struct flock lock;
    
    lock.l_type = F_WRLCK; // F_RDLCK, F_WRLCK, F_UNLCK
    lock.l_start = 0; // type offset, relative to l_whence
    lock.l_whence = SEEK_SET;  // SEEK_SET, SEEK_CUR, SEEK_END
    lock.l_len = 0;
    
    if (fcntl(fd, F_SETLK, &lock) == -1) {
        if(errno == EACCES || errno == EAGAIN) {
            ::close(fd);
            srs_error("srs is already running!");
            return srs_error_new(ERROR_SYSTEM_PID_ALREADY_RUNNING, "srs is already running");
        }
        return srs_error_new(ERROR_SYSTEM_PID_LOCK, "access to pid=%s", pid_file.c_str());
    }
    
    // truncate file
    if (ftruncate(fd, 0) != 0) {
        return srs_error_new(ERROR_SYSTEM_PID_TRUNCATE_FILE, "truncate pid file=%s", pid_file.c_str());
    }
    
    // write the pid
    string pid = srs_int2str(getpid());
    if (write(fd, pid.c_str(), pid.length()) != (int)pid.length()) {
        return srs_error_new(ERROR_SYSTEM_PID_WRITE_FILE, "write pid=%s to file=%s", pid.c_str(), pid_file.c_str());
    }
    
    // auto close when fork child process.
    int val;
    if ((val = fcntl(fd, F_GETFD, 0)) < 0) {
        return srs_error_new(ERROR_SYSTEM_PID_GET_FILE_INFO, "fcntl fd=%d", fd);
    }
    val |= FD_CLOEXEC;
    if (fcntl(fd, F_SETFD, val) < 0) {
        return srs_error_new(ERROR_SYSTEM_PID_SET_FILE_INFO, "lock file=%s fd=%d", pid_file.c_str(), fd);
    }
    
    srs_trace("write pid=%s to %s success!", pid.c_str(), pid_file.c_str());
    pid_fd = fd;
    
    return srs_success;
}

srs_error_t SrsServer::listen()
{
    srs_error_t err = srs_success;
	// ����RTMP���˿���Ϣ��_srs_config->get_listens()�����������ļ���ȡ
	// ����һ����������SrsBufferListener���˶����ڲ�����һ��SrsTcpListener����
	// �����������SrsBufferListener::listen()->SrsTcpListener::listen()
	// ÿ��SrsTcpListener�ڲ��и�Э��SrsTcpListener::cycle()�������
	// ��Э����������ʽ����srs_accept()�����յ��µĿͻ������Ӻ󣬵��� 
	// SrsBufferListener::on_tcp_client() -> SrsServer::accept_client()
	// ����SrsServer::fd_to_resource()����RTMP���Ӷ���SrsRtmpConn
	// ����SrsResourceManager::add(conn)��SrsRtmpConn��ӵ���Դ������
	// ����SrsRtmpConn::start()������ÿ�����ӵ�Э��SrsRtmpConn::do_cycle()
    if ((err = listen_rtmp()) != srs_success) {
        return srs_error_wrap(err, "rtmp listen");
    }
    // ����HTTP API
	// �˿���Ϣ��_srs_config->get_http_api_listen()�����������ļ���ȡ
	// �ڲ�Ҳͬ������SrsBufferListener�����SrsTcpListener����
	// SrsTcpListener�ڲ�Э��SrsTcpListener::cycle()�������
	// ����������ȫһ�£��������ڽ��յ������Ӻ�
	// ����SrsServer::fd_to_resource()����SrsHttp(s)Api���Ӷ���
    if ((err = listen_http_api()) != srs_success) {
        return srs_error_wrap(err, "http api listen");
    }
    // ����HTTPS API
    if ((err = listen_https_api()) != srs_success) {
        return srs_error_wrap(err, "https api listen");
    }
    // ����HTTP
	// �ڲ�������������SrsBufferListener������������ȫһ�£��������ڽ��յ������Ӻ�
	// ����SrsServer::fd_to_resource()����SrsResponseOnlyHttpConn���Ӷ���
    if ((err = listen_http_stream()) != srs_success) {
        return srs_error_wrap(err, "http stream listen");
    }
    // ����HTTPS
    if ((err = listen_https_stream()) != srs_success) {
        return srs_error_wrap(err, "https stream listen");
    }
	// �������ã��ڲ�����SrsUdpCasterListener��������
	// SrsUdpCasterListener / SrsHttpFlvListener / SrsGb28181Manger
	// ��һ���RTMP�����ϵ�������ڼ��ݶ�����ý��Э�飬�Ժ��ٵ�������
    if ((err = listen_stream_caster()) != srs_success) {
        return srs_error_wrap(err, "stream caster listen");
    }
	// ����������Դ������SrsResourceManager��Ӧ��Э��
	// ��Э���ڲ�·���Ƚϼ򵥣����ǵȴ������������ѣ�Ȼ�������ʬ����
    if ((err = conn_manager->start()) != srs_success) {
        return srs_error_wrap(err, "connection manager");
    }

    return err;
}

srs_error_t SrsServer::register_signal()
{
    srs_error_t err = srs_success;
    
    if ((err = signal_manager->start()) != srs_success) {
        return srs_error_wrap(err, "signal manager start");
    }
    
    return err;
}

srs_error_t SrsServer::http_handle()
{
    srs_error_t err = srs_success;
    
    if ((err = http_api_mux->handle("/", new SrsGoApiRoot())) != srs_success) {
        return srs_error_wrap(err, "handle /");
    }
    if ((err = http_api_mux->handle("/api/", new SrsGoApiApi())) != srs_success) {
        return srs_error_wrap(err, "handle api");
    }
    if ((err = http_api_mux->handle("/api/v1/", new SrsGoApiV1())) != srs_success) {
        return srs_error_wrap(err, "handle v1");
    }
    if ((err = http_api_mux->handle("/api/v1/versions", new SrsGoApiVersion())) != srs_success) {
        return srs_error_wrap(err, "handle versions");
    }
    if ((err = http_api_mux->handle("/api/v1/summaries", new SrsGoApiSummaries())) != srs_success) {
        return srs_error_wrap(err, "handle summaries");
    }
    if ((err = http_api_mux->handle("/api/v1/rusages", new SrsGoApiRusages())) != srs_success) {
        return srs_error_wrap(err, "handle rusages");
    }
    if ((err = http_api_mux->handle("/api/v1/self_proc_stats", new SrsGoApiSelfProcStats())) != srs_success) {
        return srs_error_wrap(err, "handle self proc stats");
    }
    if ((err = http_api_mux->handle("/api/v1/system_proc_stats", new SrsGoApiSystemProcStats())) != srs_success) {
        return srs_error_wrap(err, "handle system proc stats");
    }
    if ((err = http_api_mux->handle("/api/v1/meminfos", new SrsGoApiMemInfos())) != srs_success) {
        return srs_error_wrap(err, "handle meminfos");
    }
    if ((err = http_api_mux->handle("/api/v1/authors", new SrsGoApiAuthors())) != srs_success) {
        return srs_error_wrap(err, "handle authors");
    }
    if ((err = http_api_mux->handle("/api/v1/features", new SrsGoApiFeatures())) != srs_success) {
        return srs_error_wrap(err, "handle features");
    }
    if ((err = http_api_mux->handle("/api/v1/vhosts/", new SrsGoApiVhosts())) != srs_success) {
        return srs_error_wrap(err, "handle vhosts");
    }
    if ((err = http_api_mux->handle("/api/v1/streams/", new SrsGoApiStreams())) != srs_success) {
        return srs_error_wrap(err, "handle streams");
    }
    if ((err = http_api_mux->handle("/api/v1/clients/", new SrsGoApiClients())) != srs_success) {
        return srs_error_wrap(err, "handle clients");
    }
    if ((err = http_api_mux->handle("/api/v1/raw", new SrsGoApiRaw(this))) != srs_success) {
        return srs_error_wrap(err, "handle raw");
    }
    if ((err = http_api_mux->handle("/api/v1/clusters", new SrsGoApiClusters())) != srs_success) {
        return srs_error_wrap(err, "handle clusters");
    }
    
    // test the request info.
    if ((err = http_api_mux->handle("/api/v1/tests/requests", new SrsGoApiRequests())) != srs_success) {
        return srs_error_wrap(err, "handle tests requests");
    }
    // test the error code response.
    if ((err = http_api_mux->handle("/api/v1/tests/errors", new SrsGoApiError())) != srs_success) {
        return srs_error_wrap(err, "handle tests errors");
    }
    // test the redirect mechenism.
    if ((err = http_api_mux->handle("/api/v1/tests/redirects", new SrsHttpRedirectHandler("/api/v1/tests/errors", SRS_CONSTS_HTTP_MovedPermanently))) != srs_success) {
        return srs_error_wrap(err, "handle tests redirects");
    }
    // test the http vhost.
    if ((err = http_api_mux->handle("error.srs.com/api/v1/tests/errors", new SrsGoApiError())) != srs_success) {
        return srs_error_wrap(err, "handle tests errors for error.srs.com");
    }

#ifdef SRS_GPERF
    // The test api for get tcmalloc stats.
    // @see Memory Introspection in https://gperftools.github.io/gperftools/tcmalloc.html
    if ((err = http_api_mux->handle("/api/v1/tcmalloc", new SrsGoApiTcmalloc())) != srs_success) {
        return srs_error_wrap(err, "handle tests errors");
    }
#endif
    
    // TODO: FIXME: for console.
    // TODO: FIXME: support reload.
    std::string dir = _srs_config->get_http_stream_dir() + "/console";
    if ((err = http_api_mux->handle("/console/", new SrsHttpFileServer(dir))) != srs_success) {
        return srs_error_wrap(err, "handle console at %s", dir.c_str());
    }
    srs_trace("http: api mount /console to %s", dir.c_str());
    
    return err;
}

srs_error_t SrsServer::ingest()
{
    srs_error_t err = srs_success;
    
    if ((err = ingester->start()) != srs_success) {
        return srs_error_wrap(err, "ingest start");
    }
    
    return err;
}

srs_error_t SrsServer::start(SrsWaitGroup* wg)
{
    srs_error_t err = srs_success;

    if ((err = _srs_sources->initialize()) != srs_success) {
        return srs_error_wrap(err, "sources");
    }

    if ((err = trd_->start()) != srs_success) {
        return srs_error_wrap(err, "start");
    }

    if ((err = setup_ticks()) != srs_success) {
        return srs_error_wrap(err, "tick");
    }

    // OK, we start SRS server.
    wg_ = wg;
    wg->add(1);

    return err;
}

void SrsServer::stop()
{
#ifdef SRS_GPERF_MC
    dispose();

    // remark, for gmc, never invoke the exit().
    srs_warn("sleep a long time for system st-threads to cleanup.");
    srs_usleep(3 * 1000 * 1000);
    srs_warn("system quit");

    // For GCM, cleanup done.
    return;
#endif

    // quit normally.
    srs_warn("main cycle terminated, system quit normally.");

    // fast quit, do some essential cleanup.
    if (signal_fast_quit) {
        dispose(); // TODO: FIXME: Rename to essential_dispose.
        srs_trace("srs disposed");
    }

    // gracefully quit, do carefully cleanup.
    if (signal_gracefully_quit) {
        gracefully_dispose();
        srs_trace("srs gracefully quit");
    }

    srs_trace("srs terminated");

    // for valgrind to detect.
    srs_freep(_srs_config);
    srs_freep(_srs_log);
}

srs_error_t SrsServer::cycle()
{
    srs_error_t err = srs_success;

    // Start the inotify auto reload by watching config file.
    SrsInotifyWorker inotify(this);
    if ((err = inotify.start()) != srs_success) {
        return srs_error_wrap(err, "start inotify");
    }

    // Do server main cycle.
     err = do_cycle();

    // OK, SRS server is done.
    wg_->done();

    return err;
}

void SrsServer::on_signal(int signo)
{
    if (signo == SRS_SIGNAL_RELOAD) {
        srs_trace("reload config, signo=%d", signo);
        signal_reload = true;
        return;
    }
    
#ifndef SRS_GPERF_MC
    if (signo == SRS_SIGNAL_REOPEN_LOG) {
        _srs_log->reopen();

        if (handler) {
            handler->on_logrotate();
        }

        srs_warn("reopen log file, signo=%d", signo);
        return;
    }
#endif
    
#ifdef SRS_GPERF_MC
    if (signo == SRS_SIGNAL_REOPEN_LOG) {
        signal_gmc_stop = true;
        srs_warn("for gmc, the SIGUSR1 used as SIGINT, signo=%d", signo);
        return;
    }
#endif
    
    if (signo == SRS_SIGNAL_PERSISTENCE_CONFIG) {
        signal_persistence_config = true;
        return;
    }
    
    if (signo == SIGINT) {
#ifdef SRS_GPERF_MC
        srs_trace("gmc is on, main cycle will terminate normally, signo=%d", signo);
        signal_gmc_stop = true;
#endif
    }

    // For K8S, force to gracefully quit for gray release or canary.
    // @see https://github.com/ossrs/srs/issues/1595#issuecomment-587473037
    if (signo == SRS_SIGNAL_FAST_QUIT && _srs_config->is_force_grace_quit()) {
        srs_trace("force gracefully quit, signo=%d", signo);
        signo = SRS_SIGNAL_GRACEFULLY_QUIT;
    }

    if ((signo == SIGINT || signo == SRS_SIGNAL_FAST_QUIT) && !signal_fast_quit) {
        srs_trace("sig=%d, user terminate program, fast quit", signo);
        signal_fast_quit = true;
        return;
    }

    if (signo == SRS_SIGNAL_GRACEFULLY_QUIT && !signal_gracefully_quit) {
        srs_trace("sig=%d, user start gracefully quit", signo);
        signal_gracefully_quit = true;
        return;
    }
}

srs_error_t SrsServer::do_cycle()
{
    srs_error_t err = srs_success;
    
    // for asprocess.
    bool asprocess = _srs_config->get_asprocess();

    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "pull");
        }

        if (handler && (err = handler->on_cycle()) != srs_success) {
            return srs_error_wrap(err, "handle callback");
        }
            
        // asprocess check.
        if (asprocess && ::getppid() != ppid) {
            return srs_error_new(ERROR_ASPROCESS_PPID, "asprocess ppid changed from %d to %d", ppid, ::getppid());
        }

        // gracefully quit for SIGINT or SIGTERM or SIGQUIT.
        if (signal_fast_quit || signal_gracefully_quit) {
            srs_trace("cleanup for quit signal fast=%d, grace=%d", signal_fast_quit, signal_gracefully_quit);
            return err;
        }

        // for gperf heap checker,
        // @see: research/gperftools/heap-checker/heap_checker.cc
        // if user interrupt the program, exit to check mem leak.
        // but, if gperf, use reload to ensure main return normally,
        // because directly exit will cause core-dump.
#ifdef SRS_GPERF_MC
        if (signal_gmc_stop) {
            srs_warn("gmc got singal to stop server.");
            return err;
        }
#endif

        // do persistence config to file.
        if (signal_persistence_config) {
            signal_persistence_config = false;
            srs_info("get signal to persistence config to file.");

            if ((err = _srs_config->persistence()) != srs_success) {
                return srs_error_wrap(err, "config persistence to file");
            }
            srs_trace("persistence config to file success.");
        }

        // do reload the config.
        if (signal_reload) {
            signal_reload = false;
            srs_info("get signal to reload the config.");

            if ((err = _srs_config->reload()) != srs_success) {
                return srs_error_wrap(err, "config reload");
            }
            srs_trace("reload config success.");
        }

        srs_usleep(1 * SRS_UTIME_SECONDS);
    }
    
    return err;
}

srs_error_t SrsServer::setup_ticks()
{
    srs_error_t err = srs_success;

    srs_freep(timer_);
    timer_ = new SrsHourGlass("srs", this, 1 * SRS_UTIME_SECONDS);

    if (_srs_config->get_stats_enabled()) {
        if ((err = timer_->tick(2, 3 * SRS_UTIME_SECONDS)) != srs_success) {
            return srs_error_wrap(err, "tick");
        }
        if ((err = timer_->tick(4, 6 * SRS_UTIME_SECONDS)) != srs_success) {
            return srs_error_wrap(err, "tick");
        }
        if ((err = timer_->tick(5, 6 * SRS_UTIME_SECONDS)) != srs_success) {
            return srs_error_wrap(err, "tick");
        }
        if ((err = timer_->tick(6, 9 * SRS_UTIME_SECONDS)) != srs_success) {
            return srs_error_wrap(err, "tick");
        }
        if ((err = timer_->tick(7, 9 * SRS_UTIME_SECONDS)) != srs_success) {
            return srs_error_wrap(err, "tick");
        }

        if ((err = timer_->tick(8, 3 * SRS_UTIME_SECONDS)) != srs_success) {
            return srs_error_wrap(err, "tick");
        }

        if ((err = timer_->tick(10, 9 * SRS_UTIME_SECONDS)) != srs_success) {
            return srs_error_wrap(err, "tick");
        }
    }

    if (_srs_config->get_heartbeat_enabled()) {
        if ((err = timer_->tick(9, _srs_config->get_heartbeat_interval())) != srs_success) {
            return srs_error_wrap(err, "tick");
        }
    }

    if ((err = timer_->start()) != srs_success) {
        return srs_error_wrap(err, "timer");
    }

    return err;
}

srs_error_t SrsServer::notify(int event, srs_utime_t interval, srs_utime_t tick)
{
    srs_error_t err = srs_success;

    switch (event) {
        case 2: srs_update_system_rusage(); break;
        case 4: srs_update_disk_stat(); break;
        case 5: srs_update_meminfo(); break;
        case 6: srs_update_platform_info(); break;
        case 7: srs_update_network_devices(); break;
        case 8: resample_kbps(); break;
        case 9: http_heartbeat->heartbeat(); break;
        case 10: srs_update_udp_snmp_statistic(); break;
    }

    return err;
}

srs_error_t SrsServer::listen_rtmp()
{
    srs_error_t err = srs_success;
    
    // stream service port.
    // Ҫ�����ķ���˿ڣ������Ƕ���˿�
    std::vector<std::string> ip_ports = _srs_config->get_listens();
    srs_assert((int)ip_ports.size() > 0);
    // �ر�ָ�����͵Ķ˿ڼ�������ʼ�µļ���
    close_listeners(SrsListenerRtmpStream);
    // �����˿ڣ��������
    for (int i = 0; i < (int)ip_ports.size(); i++) {
        // ����һ����������
        SrsListener* listener = new SrsBufferListener(this, SrsListenerRtmpStream);
        listeners.push_back(listener);

        int port; string ip;
        // ������IP��port
        srs_parse_endpoint(ip_ports[i], ip, port);
        // ����
        if ((err = listener->listen(ip, port)) != srs_success) {
            srs_error_wrap(err, "rtmp listen %s:%d", ip.c_str(), port);
        }
    }
    
    return err;
}

srs_error_t SrsServer::listen_http_api()
{
    srs_error_t err = srs_success;
    
    close_listeners(SrsListenerHttpApi);
    if (_srs_config->get_http_api_enabled()) {
        SrsListener* listener = new SrsBufferListener(this, SrsListenerHttpApi);
        listeners.push_back(listener);
        
        std::string ep = _srs_config->get_http_api_listen();
        
        std::string ip;
        int port;
        srs_parse_endpoint(ep, ip, port);
        
        if ((err = listener->listen(ip, port)) != srs_success) {
            return srs_error_wrap(err, "http api listen %s:%d", ip.c_str(), port);
        }
    }
    
    return err;
}

srs_error_t SrsServer::listen_https_api()
{
    srs_error_t err = srs_success;

    close_listeners(SrsListenerHttpsApi);
    if (_srs_config->get_https_api_enabled()) {
        SrsListener* listener = new SrsBufferListener(this, SrsListenerHttpsApi);
        listeners.push_back(listener);

        std::string ep = _srs_config->get_https_api_listen();

        std::string ip;
        int port;
        srs_parse_endpoint(ep, ip, port);

        if ((err = listener->listen(ip, port)) != srs_success) {
            return srs_error_wrap(err, "https api listen %s:%d", ip.c_str(), port);
        }
    }

    return err;
}

srs_error_t SrsServer::listen_http_stream()
{
    srs_error_t err = srs_success;
    
    close_listeners(SrsListenerHttpStream);
    if (_srs_config->get_http_stream_enabled()) {
        SrsListener* listener = new SrsBufferListener(this, SrsListenerHttpStream);
        listeners.push_back(listener);
        
        std::string ep = _srs_config->get_http_stream_listen();
        
        std::string ip;
        int port;
        srs_parse_endpoint(ep, ip, port);
        
        if ((err = listener->listen(ip, port)) != srs_success) {
            return srs_error_wrap(err, "http stream listen %s:%d", ip.c_str(), port);
        }
    }
    
    return err;
}

srs_error_t SrsServer::listen_https_stream()
{
    srs_error_t err = srs_success;

    close_listeners(SrsListenerHttpsStream);
    if (_srs_config->get_https_stream_enabled()) {
        SrsListener* listener = new SrsBufferListener(this, SrsListenerHttpsStream);
        listeners.push_back(listener);

        std::string ep = _srs_config->get_https_stream_listen();

        std::string ip;
        int port;
        srs_parse_endpoint(ep, ip, port);

        if ((err = listener->listen(ip, port)) != srs_success) {
            return srs_error_wrap(err, "https stream listen %s:%d", ip.c_str(), port);
        }
    }

    return err;
}

srs_error_t SrsServer::listen_stream_caster()
{
    srs_error_t err = srs_success;
    
    close_listeners(SrsListenerMpegTsOverUdp);
    
    std::vector<SrsConfDirective*>::iterator it;
    std::vector<SrsConfDirective*> stream_casters = _srs_config->get_stream_casters();
    
    for (it = stream_casters.begin(); it != stream_casters.end(); ++it) {
        SrsConfDirective* stream_caster = *it;
        if (!_srs_config->get_stream_caster_enabled(stream_caster)) {
            continue;
        }
        
        SrsListener* listener = NULL;
        
        std::string caster = _srs_config->get_stream_caster_engine(stream_caster);
        if (srs_stream_caster_is_udp(caster)) {
            listener = new SrsUdpCasterListener(this, SrsListenerMpegTsOverUdp, stream_caster);
        } else if (srs_stream_caster_is_flv(caster)) {
            listener = new SrsHttpFlvListener(this, SrsListenerFlv, stream_caster);
        } else {
            return srs_error_new(ERROR_STREAM_CASTER_ENGINE, "invalid caster %s", caster.c_str());
        }
        srs_assert(listener != NULL);
        
        listeners.push_back(listener);
        int port = _srs_config->get_stream_caster_listen(stream_caster);
        if (port <= 0) {
            return srs_error_new(ERROR_STREAM_CASTER_PORT, "invalid port=%d", port);
        }
        // TODO: support listen at <[ip:]port>
        if ((err = listener->listen(srs_any_address_for_listener(), port)) != srs_success) {
            return srs_error_wrap(err, "listen at %d", port);
        }
    }
    
    return err;
}

void SrsServer::close_listeners(SrsListenerType type)
{
    std::vector<SrsListener*>::iterator it;
    for (it = listeners.begin(); it != listeners.end();) {
        SrsListener* listener = *it;
        
        if (listener->listen_type() != type) {
            ++it;
            continue;
        }
        
        srs_freep(listener);
        it = listeners.erase(it);
    }
}

void SrsServer::resample_kbps()
{
    SrsStatistic* stat = SrsStatistic::instance();
    
    // collect delta from all clients.
    for (int i = 0; i < (int)conn_manager->size(); i++) {
        ISrsResource* c = conn_manager->at(i);
        ISrsKbpsDelta* conn = dynamic_cast<ISrsKbpsDelta*>(conn_manager->at(i));
        
        // add delta of connection to server kbps.,
        // for next sample() of server kbps can get the stat.
        stat->kbps_add_delta(c->get_id().c_str(), conn);
    }
    
    // TODO: FXME: support all other connections.
    
    // sample the kbps, get the stat.
    SrsKbps* kbps = stat->kbps_sample();
    
    srs_update_rtmp_server((int)conn_manager->size(), kbps);
}

srs_error_t SrsServer::accept_client(SrsListenerType type, srs_netfd_t stfd)
{
    srs_error_t err = srs_success;
    
    ISrsStartableConneciton* conn = NULL;
	// ����SrsServer::fd_to_resource()������SrsListenerType���������ɲ�ͬ�����Ӷ���
	// SrsRtmpConn��SrsHttpApi��SrsResponseOnlyHttpConn
    if ((err = fd_to_resource(type, stfd, &conn)) != srs_success) {
        if (srs_error_code(err) == ERROR_SOCKET_GET_PEER_IP && _srs_config->empty_ip_ok()) {
            srs_close_stfd(stfd); srs_error_reset(err);
            return srs_success;
        }
        return srs_error_wrap(err, "fd to resource");
    }
    srs_assert(conn);
    
    // directly enqueue, the cycle thread will remove the client.
    conn_manager->add(conn);
	// �������Ӷ���conn�ڲ���Э��
	// 1��SrsRtmpConn����������Э����SrsRtmpConn::do_cycle()
	// 2��SrsHttpApi��SrsResponseOnlyHttpConn���Ӷ����ڲ�����һ��SrsHttpConn���� ��������������Э����SrsHttpConn::do_cycle()
    if ((err = conn->start()) != srs_success) {
        return srs_error_wrap(err, "start conn coroutine");
    }
    
    return err;
}

SrsHttpServeMux* SrsServer::api_server()
{
    return http_api_mux;
}

srs_error_t SrsServer::fd_to_resource(SrsListenerType type, srs_netfd_t stfd, ISrsStartableConneciton** pr)
{
    srs_error_t err = srs_success;
    // ��ȡ����ϵͳ��socket�ļ�������
    int fd = srs_netfd_fileno(stfd);
    string ip = srs_get_peer_ip(fd);
    int port = srs_get_peer_port(fd);
    
    // for some keep alive application, for example, the keepalived,
    // will send some tcp packet which we cann't got the ip,
    // we just ignore it.
    if (ip.empty()) {
        return srs_error_new(ERROR_SOCKET_GET_PEER_IP, "ignore empty ip, fd=%d", fd);
    }
    
    // check connection limitation.
    // ������������ rtmp http ���е�����
    int max_connections = _srs_config->get_max_connections();
    if (handler && (err = handler->on_accept_client(max_connections, (int)conn_manager->size())) != srs_success) {
        return srs_error_wrap(err, "drop client fd=%d, ip=%s:%d, max=%d, cur=%d for err: %s",
            fd, ip.c_str(), port, max_connections, (int)conn_manager->size(), srs_error_desc(err).c_str());
    }
    if ((int)conn_manager->size() >= max_connections) {
        return srs_error_new(ERROR_EXCEED_CONNECTIONS, "drop fd=%d, ip=%s:%d, max=%d, cur=%d for exceed connection limits",
            fd, ip.c_str(), port, max_connections, (int)conn_manager->size());
    }
    
    // avoid fd leak when fork.
    // @see https://github.com/ossrs/srs/issues/518
    if (true) {
        int val;
        if ((val = fcntl(fd, F_GETFD, 0)) < 0) {
            return srs_error_new(ERROR_SYSTEM_PID_GET_FILE_INFO, "fnctl F_GETFD error! fd=%d", fd);
        }
        val |= FD_CLOEXEC;
        if (fcntl(fd, F_SETFD, val) < 0) {
            return srs_error_new(ERROR_SYSTEM_PID_SET_FILE_INFO, "fcntl F_SETFD error! fd=%d", fd);
        }
    }

    // The context id may change during creating the bellow objects.
    SrsContextRestore(_srs_context->get_id());
    
    if (type == SrsListenerRtmpStream) {
        *pr = new SrsRtmpConn(this, stfd, ip, port);
    } else if (type == SrsListenerHttpApi) {
        *pr = new SrsHttpApi(false, this, stfd, http_api_mux, ip, port);
    } else if (type == SrsListenerHttpsApi) {
        *pr = new SrsHttpApi(true, this, stfd, http_api_mux, ip, port);
    } else if (type == SrsListenerHttpStream) {
        *pr = new SrsResponseOnlyHttpConn(false, this, stfd, http_server, ip, port);
    } else if (type == SrsListenerHttpsStream) {
        *pr = new SrsResponseOnlyHttpConn(true, this, stfd, http_server, ip, port);
    } else {
        srs_warn("close for no service handler. fd=%d, ip=%s:%d", fd, ip.c_str(), port);
        srs_close_stfd(stfd);
        return err;
    }
    
    return err;
}

void SrsServer::remove(ISrsResource* c)
{
    ISrsStartableConneciton* conn = dynamic_cast<ISrsStartableConneciton*>(c);

    SrsStatistic* stat = SrsStatistic::instance();
    stat->kbps_add_delta(c->get_id().c_str(), conn);
    stat->on_disconnect(c->get_id().c_str());

    // use manager to free it async.
    conn_manager->remove(c);
}

srs_error_t SrsServer::on_reload_listen()
{
    srs_error_t err = srs_success;
    
    if ((err = listen()) != srs_success) {
        return srs_error_wrap(err, "reload listen");
    }
    
    return err;
}

srs_error_t SrsServer::on_reload_pid()
{
    srs_error_t err = srs_success;
    
    if (pid_fd > 0) {
        ::close(pid_fd);
        pid_fd = -1;
    }
    
    if ((err = acquire_pid_file()) != srs_success) {
        return srs_error_wrap(err, "reload pid");
    }
    
    return err;
}

srs_error_t SrsServer::on_reload_vhost_added(std::string vhost)
{
    srs_error_t err = srs_success;
    
    if (!_srs_config->get_vhost_http_enabled(vhost)) {
        return err;
    }
    
    // TODO: FIXME: should handle the event in SrsHttpStaticServer
    if ((err = on_reload_vhost_http_updated()) != srs_success) {
        return srs_error_wrap(err, "reload vhost added");
    }
    
    return err;
}

srs_error_t SrsServer::on_reload_vhost_removed(std::string /*vhost*/)
{
    srs_error_t err = srs_success;
    
    // TODO: FIXME: should handle the event in SrsHttpStaticServer
    if ((err = on_reload_vhost_http_updated()) != srs_success) {
        return srs_error_wrap(err, "reload vhost removed");
    }
    
    return err;
}

srs_error_t SrsServer::on_reload_http_api_enabled()
{
    srs_error_t err = srs_success;
    
    if ((err = listen_http_api()) != srs_success) {
        return srs_error_wrap(err, "reload http_api");
    }

    if ((err = listen_https_api()) != srs_success) {
        return srs_error_wrap(err, "reload https_api");
    }
    
    return err;
}

srs_error_t SrsServer::on_reload_http_api_disabled()
{
    close_listeners(SrsListenerHttpApi);
    close_listeners(SrsListenerHttpsApi);
    return srs_success;
}

srs_error_t SrsServer::on_reload_http_stream_enabled()
{
    srs_error_t err = srs_success;
    
    if ((err = listen_http_stream()) != srs_success) {
        return srs_error_wrap(err, "reload http_stream enabled");
    }

    if ((err = listen_https_stream()) != srs_success) {
        return srs_error_wrap(err, "reload https_stream enabled");
    }
    
    return err;
}

srs_error_t SrsServer::on_reload_http_stream_disabled()
{
    close_listeners(SrsListenerHttpStream);
    close_listeners(SrsListenerHttpsStream);
    return srs_success;
}

// TODO: FIXME: rename to http_remux
srs_error_t SrsServer::on_reload_http_stream_updated()
{
    srs_error_t err = srs_success;
    
    if ((err = on_reload_http_stream_enabled()) != srs_success) {
        return srs_error_wrap(err, "reload http_stream updated");
    }
    
    // TODO: FIXME: should handle the event in SrsHttpStaticServer
    if ((err = on_reload_vhost_http_updated()) != srs_success) {
        return srs_error_wrap(err, "reload http_stream updated");
    }
    
    return err;
}

srs_error_t SrsServer::on_publish(SrsLiveSource* s, SrsRequest* r)
{
    srs_error_t err = srs_success;
    
    if ((err = http_server->http_mount(s, r)) != srs_success) {
        return srs_error_wrap(err, "http mount");
    }
    
    SrsCoWorkers* coworkers = SrsCoWorkers::instance();
    if ((err = coworkers->on_publish(s, r)) != srs_success) {
        return srs_error_wrap(err, "coworkers");
    }
    
    return err;
}

void SrsServer::on_unpublish(SrsLiveSource* s, SrsRequest* r)
{
    http_server->http_unmount(s, r);
    
    SrsCoWorkers* coworkers = SrsCoWorkers::instance();
    coworkers->on_unpublish(s, r);
}

SrsServerAdapter::SrsServerAdapter()
{
    srs = new SrsServer();
}

SrsServerAdapter::~SrsServerAdapter()
{
    srs_freep(srs);
}

srs_error_t SrsServerAdapter::initialize()
{
    srs_error_t err = srs_success;
    return err;
}
/*
初始化整个系统
*/
srs_error_t SrsServerAdapter::run(SrsWaitGroup* wg)
{
    srs_error_t err = srs_success;

    // Initialize the whole system, set hooks to handle server level events.
    // 此函数内部主要是调用 SrsHttpServeMux 和 SrsHttpServer 对象的初始化
    // SrsHttpServeMux 负责 HTTP API 的注册和处理
    // SrsHttpServer 内部包括 SrsHttpStaticServer 和 SrsHttpStreamServer 对象
    // SrsHttpStaticServer 提供静态文件的读取服务
    // SrsHttpStreamServer 提供 http FLV/TS/MP3/AAC 流数据服务
    if ((err = srs->initialize(NULL)) != srs_success) {
        return srs_error_wrap(err, "server initialize");
    }

    if ((err = srs->initialize_st()) != srs_success) {
        return srs_error_wrap(err, "initialize st");
    }
    // pid文件用于防止SRS服务进程被多次重复启动，只有获得特定pid文件(固定路径和文件名)的写入权限(独占性写文件锁F_WRLCK)的进程才能正常启动
    // 并将自身的进程PID写入该文件，其它同一程序的多余进程则自动退出
    if ((err = srs->acquire_pid_file()) != srs_success) {
        return srs_error_wrap(err, "acquire pid file");
    }
    // 内部调用pipe()函数创建读写管道，此管道用于传递信号(signal)
    // 以及创建版本信息的协程
    if ((err = srs->initialize_signal()) != srs_success) {
        return srs_error_wrap(err, "initialize signal");
    }
    // ★★★ 监听 rtmp/http api/http stream的请求 ★★★
    if ((err = srs->listen()) != srs_success) {
        return srs_error_wrap(err, "listen");
    }
    // 此函数内部使用sigemptyset和sigaction注册信号处理函数sig_catcher()
    // 信号处理函数sig_catcher()内部在接收到系统signal时，将signal写入前面创建的pipe管道
    if ((err = srs->register_signal()) != srs_success) {
        return srs_error_wrap(err, "register signal");
    }
    // 此函数内部，将字符串形式的HTTP API和对应的处理函数注册到SrsHttpServeMux对象内，
    // 后续，当SrsHttpServeMux收到某个API请求后，则调用对应的处理函数
    if ((err = srs->http_handle()) != srs_success) {
        return srs_error_wrap(err, "http handle");
    }
    // 启动拉取服务SrsIngester对象的内部工作协程，用于从文件、流、设备中拉取音视频流
    if ((err = srs->ingest()) != srs_success) {
        return srs_error_wrap(err, "ingest");
    }
    // 这里的工作包括:
    // 1)初始化SrsLiveSourceManager对象，SrsLiveSourceManager主要工作是通过周期性轮询检测
    //     定时清理长期没有有效数据SrsLiveSource对象
    // 2)启动SrsServer的内部协程，此协程的主要工作是轮询信号标志，重新加载新配置文件
    // 3)调用SrsServer::setup_ticks()创建SrsServer内部周期定时器、注册定时器事件并启动定时器协程
    //     在函数SrsServer::notify()内部，执行上述周期定时器的超时处理
    if ((err = srs->start(wg)) != srs_success) {
        return srs_error_wrap(err, "start");
    }

    return err;
}

void SrsServerAdapter::stop()
{
}

SrsServer* SrsServerAdapter::instance()
{
    return srs;
}

