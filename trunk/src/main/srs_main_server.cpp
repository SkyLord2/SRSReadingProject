//
// Copyright (c) 2013-2021 The SRS Authors
//
// SPDX-License-Identifier: MIT or MulanPSL-2.0
//

#include <srs_core.hpp>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sstream>
using namespace std;

#ifdef SRS_GPERF_MP
#include <gperftools/heap-profiler.h>
#endif
#ifdef SRS_GPERF_CP
#include <gperftools/profiler.h>
#endif

#ifdef SRS_GPERF
#include <gperftools/malloc_extension.h>
#endif

#include <unistd.h>
using namespace std;

#include <srs_kernel_error.hpp>
#include <srs_app_server.hpp>
#include <srs_app_config.hpp>
#include <srs_app_log.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_core_performance.hpp>
#include <srs_app_utility.hpp>
#include <srs_core_autofree.hpp>
#include <srs_kernel_file.hpp>
#include <srs_app_hybrid.hpp>
#include <srs_app_threads.hpp>
#ifdef SRS_RTC
#include <srs_app_rtc_conn.hpp>
#include <srs_app_rtc_server.hpp>
#endif

#ifdef SRS_SRT
#include <srt_server.hpp>
#endif

// pre-declare
srs_error_t run_directly_or_daemon();
srs_error_t srs_detect_docker();
srs_error_t run_hybrid_server();
void show_macro_features();

// @global log and context.
ISrsLog* _srs_log = NULL;
ISrsContext* _srs_context = NULL;
// @global config object for app module.
SrsConfig* _srs_config = NULL;

// @global version of srs, which can grep keyword "XCORE"
extern const char* _srs_version;

// @global main SRS server, for debugging
SrsServer* _srs_server = NULL;

/**
 * main entrance.
 * 主入口处理函数
 */
srs_error_t do_main(int argc, char** argv)
{
    srs_error_t err = srs_success;

    // Initialize global or thread-local variables.
    // 初始化协程相关的功能
    // 此函数内部创建_srs_log、_srs_context、_srs_config全局对象
    // 并调用StateThreads库的初始化函数，创建Idle协程（负责epoll和轮询定时器）
    // 创建全局管理对象SrsHybridServer、SrsLiveSourceManager、SrsRtcSourceManager、SrsResourceManager
    if ((err = srs_thread_initialize()) != srs_success) {
        return srs_error_wrap(err, "thread init");
    }

    // For background context id.
    // 生成一个随机字符串，设置主协程的id
    _srs_context->set_id(_srs_context->generate_id());

    // TODO: support both little and big endian.
    // 是否为小端模式
    srs_assert(srs_is_little_endian());
    
    // for gperf gmp or gcp,
    // should never enable it when not enabled for performance issue.
#ifdef SRS_GPERF_MP
    HeapProfilerStart("gperf.srs.gmp");
#endif
#ifdef SRS_GPERF_CP
    ProfilerStart("gperf.srs.gcp");
#endif
    
    // never use gmp to check memory leak.
#ifdef SRS_GPERF_MP
#warning "gmp is not used for memory leak, please use gmc instead."
#endif

    // Ignore any error while detecting docker.
    // 检测是否在docker环境, _srs_in_docker = true or false
    if ((err = srs_detect_docker()) != srs_success) {
        srs_error_reset(err);
    }
    
    // never use srs log(srs_trace, srs_error, etc) before config parse the option,
    // which will load the log config and apply it.
    // 解析配置文件
    if ((err = _srs_config->parse_options(argc, argv)) != srs_success) {
        return srs_error_wrap(err, "config parse options");
    }

    if (_srs_config->get_object_detection_enabled()) {
        srs_trace("object detection is enabled");
    }
    // change the work dir and set cwd.
    int r0 = 0;
    // 获取工作目录
    string cwd = _srs_config->get_work_dir();
    if (!cwd.empty() && cwd != "./" && (r0 = chdir(cwd.c_str())) == -1) {
        return srs_error_new(-1, "chdir to %s, r0=%d", cwd.c_str(), r0);
    }
    if ((err = _srs_config->initialize_cwd()) != srs_success) {
        return srs_error_wrap(err, "config cwd");
    }
    
    // config parsed, initialize log.
    // 配置解析完毕，初始化日志
    if ((err = _srs_log->initialize()) != srs_success) {
        return srs_error_wrap(err, "log initialize");
    }
    
    // config already applied to log.
    srs_trace2(TAG_MAIN, "%s, %s", RTMP_SIG_SRS_SERVER, RTMP_SIG_SRS_LICENSE);
    srs_trace("authors: %sand %s", RTMP_SIG_SRS_AUTHORS, SRS_CONSTRIBUTORS);
    srs_trace("cwd=%s, work_dir=%s, build: %s, configure: %s, uname: %s, osx: %d, pkg: %s, source: %s, mgmt: %s",
        _srs_config->cwd().c_str(), cwd.c_str(), SRS_BUILD_DATE, SRS_USER_CONFIGURE, SRS_UNAME, SRS_OSX_BOOL, SRS_PACKAGER,
        srs_getenv("SRS_REGION").c_str(), srs_getenv("SRS_SOURCE").c_str(), srs_getenv("SRS_MGMT").c_str());
    srs_trace("configure detail: " SRS_CONFIGURE);
#ifdef SRS_EMBEDED_TOOL_CHAIN
    srs_trace("crossbuild tool chain: " SRS_EMBEDED_TOOL_CHAIN);
#endif

    // for memory check or detect.
    if (true) {
        stringstream ss;
        
#ifdef SRS_PERF_GLIBC_MEMORY_CHECK
        // 读取并设置环境变量
        // ensure glibc write error to stderr.
        // 设置LIBC_FATAL_STDERR_=1, 可以将这些内存错误信息输出到stderr
        string lfsov = srs_getenv("LIBC_FATAL_STDERR_");
        setenv("LIBC_FATAL_STDERR_", "1", 1);
        string lfsnv = srs_getenv("LIBC_FATAL_STDERR_");
        //
        // ensure glibc to do alloc check.
        // Linux下提供的MALLOC_CHECK可以检测malloc和free的问题，GNU C Library 可以根据环境变量MALLOC_CHECK_来决定是否在运行时可检测程序中的内存问题。而内存问题有时候表现得非常古怪，比如random crash, crash的点又经常变，甚至coredump中也没什么栈信息。这时候可以用这个方法来验证一下。只是还没办法打印出错点对应的地址，有些遗憾。
        // MALLOC_CHECK_ = 0, 和没设置一样，将忽略这些错误
        // MALLOC_CHECK_ = 1, 将打印一个错误告警
        // MALLOC_CHECK_ = 2, 程序将收到SIGABRT信号退出
        string mcov = srs_getenv("MALLOC_CHECK_");
        setenv("MALLOC_CHECK_", "1", 1);
        string mcnv = srs_getenv("MALLOC_CHECK_");
        ss << "glic mem-check env MALLOC_CHECK_ " << mcov << "=>" << mcnv << ", LIBC_FATAL_STDERR_ " << lfsov << "=>" << lfsnv << ".";
#endif
        
#ifdef SRS_GPERF_MC
        // tcmalloc是一个类似于malloc的内存分配库，但同时提供了内存泄露，内存越界以及野指针检测与内存分析的功能
        // 设置环境变量HEAPCHECK=normal/strict/draconian,对整个程序进行检查
        // 对部分代码进行检查：
        // HeapProfileLeakChecker checker("foo");
        // foo();    //待检查部分

        assert(checker.NoLeaks());
        string hcov = srs_getenv("HEAPCHECK");
        if (hcov.empty()) {
            string cpath = _srs_config->config();
            srs_warn("gmc HEAPCHECK is required, for example: env HEAPCHECK=normal ./objs/srs -c %s", cpath.c_str());
        } else {
            ss << "gmc env HEAPCHECK=" << hcov << ".";
        }
#endif
        
#ifdef SRS_GPERF_MD
        // 打开内存越界检查，在分配时分配到页的底部，这样越界时就会报错了。也就是PAGE_FENCE
        // 局限是只能对heap做越界读写的检查
        char* TCMALLOC_PAGE_FENCE = getenv("TCMALLOC_PAGE_FENCE");
        if (!TCMALLOC_PAGE_FENCE || strcmp(TCMALLOC_PAGE_FENCE, "1")) {
            srs_warn("gmd enabled without env TCMALLOC_PAGE_FENCE=1");
        } else {
            ss << "gmd env TCMALLOC_PAGE_FENCE=" << TCMALLOC_PAGE_FENCE << ".";
        }
#endif
        
        string sss = ss.str();
        if (!sss.empty()) {
            srs_trace(sss.c_str());
        }
    }
    
    // we check the config when the log initialized.
    // 检查配置文件是否正确，检查命令是否合法，检查系统的最大连接限制
    if ((err = _srs_config->check_config()) != srs_success) {
        return srs_error_wrap(err, "check config");
    }
    
    // features
    // 打印当前采用的配置
    show_macro_features();

#ifdef SRS_GPERF
    // For tcmalloc, use slower release rate.
    if (true) {
        double trr = _srs_config->tcmalloc_release_rate();
        double otrr = MallocExtension::instance()->GetMemoryReleaseRate();
        MallocExtension::instance()->SetMemoryReleaseRate(trr);
        srs_trace("tcmalloc: set release-rate %.2f=>%.2f", otrr, trr);
    }
#endif
    // 此函数内部判断是否需要以后台模式运行，并启动全部服务
    if ((err = run_directly_or_daemon()) != srs_success) {
        return srs_error_wrap(err, "run");
    }
    
    return err;
}

int main(int argc, char** argv)
{
    srs_error_t err = do_main(argc, argv);

    if (err != srs_success) {
        srs_error("Failed, %s", srs_error_desc(err).c_str());
    }
    
    int ret = srs_error_code(err);
    srs_freep(err);
    return ret;
}

/**
 * show the features by macro, the actual macro values.
 */
void show_macro_features()
{
    if (true) {
        stringstream ss;
        
        ss << "features";
        
        // rch(rtmp complex handshake)
        // 握手
        ss << ", rch:" << srs_bool2switch(true);
        ss << ", dash:" << "on";
        ss << ", hls:" << srs_bool2switch(true);
        ss << ", hds:" << srs_bool2switch(SRS_HDS_BOOL);
        ss << ", srt:" << srs_bool2switch(SRS_SRT_BOOL);
        // hc(http callback)
        ss << ", hc:" << srs_bool2switch(true);
        // ha(http api)
        ss << ", ha:" << srs_bool2switch(true);
        // hs(http server)
        ss << ", hs:" << srs_bool2switch(true);
        // hp(http parser)
        ss << ", hp:" << srs_bool2switch(true);
        ss << ", dvr:" << srs_bool2switch(true);
        // trans(transcode)
        ss << ", trans:" << srs_bool2switch(true);
        // inge(ingest)
        ss << ", inge:" << srs_bool2switch(true);
        ss << ", stat:" << srs_bool2switch(true);
        // sc(stream-caster)
        ss << ", sc:" << srs_bool2switch(true);
        srs_trace(ss.str().c_str());
    }
    
    if (true) {
        stringstream ss;
        ss << "SRS on ";
#if defined(__amd64__)
        ss << " amd64";
#endif
#if defined(__x86_64__)
        ss << " x86_64";
#endif
#if defined(__i386__)
        ss << " i386";
#endif
#if defined(__arm__)
        ss << "arm";
#endif
#if defined(__aarch64__)
        ss << " aarch64";
#endif
#if defined(SRS_CROSSBUILD)
        ss << "(crossbuild)";
#endif
        
        ss << ", conf:" << _srs_config->config() << ", limit:" << _srs_config->get_max_connections()
        << ", writev:" << sysconf(_SC_IOV_MAX) << ", encoding:" << (srs_is_little_endian()? "little-endian":"big-endian")
        << ", HZ:" << (int)sysconf(_SC_CLK_TCK);
        
        srs_trace(ss.str().c_str());
    }
    
    if (true) {
        stringstream ss;
        
        // mw(merged-write)
        // 服务端为了提供效率，也会进行merged-write,也就是一次发送几毫秒的数据到客户端，
        // 这个同样也会导致延迟。好处是可以支持的客户端会变多。
        // 所以在低延迟的场景中我们需要根据要求进行权衡，将这个设置到较小的值。
        ss << "mw sleep:" << srsu2msi(SRS_PERF_MW_SLEEP) << "ms";
        
        // mr(merged-read)
        ss << ". mr ";
#ifdef SRS_PERF_MERGED_READ
        ss << "enabled:on";
#else
        ss << "enabled:off";
#endif
        ss << ", default:" << SRS_PERF_MR_ENABLED << ", sleep:" << srsu2msi(SRS_PERF_MR_SLEEP) << "ms";
        
        srs_trace(ss.str().c_str());
    }
    
    if (true) {
        stringstream ss;
        
        // gc(gop-cache)
        // 为了减肥低延迟，服务端可以关闭GOP缓存，不缓存前一个GOP。
        ss << "gc:" << srs_bool2switch(SRS_PERF_GOP_CACHE);
        // pq(play-queue)
        ss << ", pq:" << srsu2msi(SRS_PERF_PLAY_QUEUE) << "ms";
        // cscc(chunk stream cache cid)
        ss << ", cscc:[0," << SRS_PERF_CHUNK_STREAM_CACHE << ")";
        // csa(complex send algorithm)
        ss << ", csa:";
#ifndef SRS_PERF_COMPLEX_SEND
        ss << "off";
#else
        ss << "on";
#endif
        
        // tn(TCP_NODELAY)
        ss << ", tn:";
#ifdef SRS_PERF_TCP_NODELAY
        ss << "on(may hurts performance)";
#else
        ss << "off";
#endif
        
        // ss(SO_SENDBUF)
        ss << ", ss:";
#ifdef SRS_PERF_SO_SNDBUF_SIZE
        ss << SRS_PERF_SO_SNDBUF_SIZE;
#else
        ss << "auto(guess by merged write)";
#endif
        
        srs_trace(ss.str().c_str());
    }
    
    // others
    int possible_mr_latency = 0;
#ifdef SRS_PERF_MERGED_READ
    possible_mr_latency = srsu2msi(SRS_PERF_MR_SLEEP);
#endif
    srs_trace("system default latency(ms): mw(0-%d) + mr(0-%d) + play-queue(0-%d)",
              srsu2msi(SRS_PERF_MW_SLEEP), possible_mr_latency, srsu2msi(SRS_PERF_PLAY_QUEUE));
    
#if VERSION_MAJOR > VERSION_STABLE
    #warning "Current branch is not stable."
    srs_warn("%s/%s is not stable", RTMP_SIG_SRS_KEY, RTMP_SIG_SRS_VERSION);
#endif
    
#if defined(SRS_PERF_SO_SNDBUF_SIZE) && !defined(SRS_PERF_MW_SO_SNDBUF)
#error "SRS_PERF_SO_SNDBUF_SIZE depends on SRS_PERF_MW_SO_SNDBUF"
#endif
}

// Detect docker by https://stackoverflow.com/a/41559867
bool _srs_in_docker = false;
srs_error_t srs_detect_docker()
{
    srs_error_t err = srs_success;

    _srs_in_docker = false;

    SrsFileReader fr;
    if ((err = fr.open("/proc/1/cgroup")) != srs_success) {
        return err;
    }

    ssize_t nn;
    char buf[1024];
    if ((err = fr.read(buf, sizeof(buf), &nn)) != srs_success) {
        return err;
    }

    if (nn <= 0) {
        return err;
    }

    string s(buf, nn);
    if (srs_string_contains(s, "/docker")) {
        _srs_in_docker = true;
    }

    return err;
}
/// <summary>
/// 此函数内部判断是否需要以后台模式运行，并启动全部服务
/// </summary>
/// <returns>
/// 返回 成功或者失败
/// </returns>
srs_error_t run_directly_or_daemon()
{
    srs_error_t err = srs_success;

    // Try to load the config if docker detect failed.
    // docker 环境监测失败，从配置文件中读取是否处于docker环境中
    if (!_srs_in_docker) {
        _srs_in_docker = _srs_config->get_in_docker();
        if (_srs_in_docker) {
            srs_trace("enable in_docker by config");
        }
    }

    // Load daemon from config, disable it for docker.
    // @see https://github.com/ossrs/srs/issues/1594
    // 在 docker 环境中，如果设置 disable_daemon_for_docker 为 on (默认设置为on), 则取消后台运行
    bool run_as_daemon = _srs_config->get_daemon();
    if (run_as_daemon && _srs_in_docker && _srs_config->disable_daemon_for_docker()) {
        srs_warn("disable daemon for docker");
        run_as_daemon = false;
    }
    
    // If not daemon, directly run hybrid server.
    // 非后台运行，直接启动服务
    if (!run_as_daemon) {
        if ((err = run_hybrid_server()) != srs_success) {
            return srs_error_wrap(err, "run hybrid");
        }
        return srs_success;
    }
    
    srs_trace("start daemon mode...");
    
    int pid = fork();
    
    if(pid < 0) {
        return srs_error_new(-1, "fork father process");
    }
    
    // grandpa
    if(pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        srs_trace("grandpa process exit.");
        exit(0);
    }
    
    // father
    pid = fork();
    
    if(pid < 0) {
        return srs_error_new(-1, "fork child process");
    }
    
    if(pid > 0) {
        srs_trace("father process exit");
        exit(0);
    }
    
    // son
    srs_trace("son(daemon) process running.");
    
    if ((err = run_hybrid_server()) != srs_success) {
        return srs_error_wrap(err, "daemon run hybrid");
    }
    
    return err;
}
/// <summary>
/// 创建启动各项服务
/// </summary>
/// <returns></returns>
srs_error_t run_hybrid_server()
{
    srs_error_t err = srs_success;
    // Create servers and register them.
    // _srs_hybrid指向一个全局SrsHybridServer对象
    // 实际工作对象SrsServerAdapter和RtcServerAdapter被注入到SrsHybridServer对象内部
    _srs_hybrid->register_server(new SrsServerAdapter());

#ifdef SRS_SRT
    _srs_hybrid->register_server(new SrtServerAdapter());
#endif

#ifdef SRS_RTC
    _srs_hybrid->register_server(new RtcServerAdapter());
#endif

    // Do some system initialize.
    // 此函数内部分别启动几个周期定时器，
    // 并以遍历方式调用上面已注册服务器的initialize()函数
    if ((err = _srs_hybrid->initialize()) != srs_success) {
        return srs_error_wrap(err, "hybrid initialize");
    }

    // Circuit breaker to protect server, which depends on hybrid.
    // 此模块用于防止服务器过载，实现过载保护
    if ((err = _srs_circuit_breaker->initialize()) != srs_success) {
        return srs_error_wrap(err, "init circuit breaker");
    }

    // Should run util hybrid servers all done.
    // 此函数内部以遍历方式调用上面已注册服务器的run接口，并在最后
    // 调用srs_usleep(SRS_UTIME_NO_TIMEOUT)使当前的原始协程进入休眠状态
    if ((err = _srs_hybrid->run()) != srs_success) {
        return srs_error_wrap(err, "hybrid run");
    }

    // After all done, stop and cleanup.
    // 如果执行到这里，表示整个服务已结束，程序即将退出
    _srs_hybrid->stop();

    return err;
}

