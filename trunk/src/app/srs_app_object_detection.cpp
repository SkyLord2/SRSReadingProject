//
// Created by cds on 22-9-11.
//
#include <unistd.h>
#include <srs_app_object_detection.hpp>
#include <srs_app_config.hpp>
#include <srs_kernel_error.hpp>
#include <srs_app_uuid.hpp>
#include <opencv2/opencv.hpp>

using namespace cv;
using namespace std;

SrsObjectDetection::SrsObjectDetection() {

}

SrsObjectDetection::~SrsObjectDetection() {

}

srs_error_t SrsObjectDetection::on_publish(SrsRequest *r) {
    srs_error_t err = srs_success;
    if (!_srs_config->get_object_detection_enabled()){
        srs_trace("object detection is not enable");
        return err;
    }
    srs_trace("object detection is enabled");
    static pid_t pid = -1;
    static int fd[2];

    if (pid == -1) {
        if (pipe(fd) < 0) {
            return srs_error_new(ERROR_PIPE_CREATE, "linux pipe create failed");
        }
        pid = fork();
        if (pid < 0) {
            return srs_error_new(ERROR_OBJECT_DETECTION_FORK, "linux fork failed");
        }
    }
    if (pid == 0) {
        srs_trace("sub process create success");
        // fd[0] reading, fd[1] writing, close writing and open reading
        close(fd[1]);
        int ret_W;
        char buf[256];
        while (ret_W = read(fd[0], buf, sizeof buf)) {
            srs_trace("the published stream url is %s", buf);
            do_object_detection(buf);
        }
    } else {
        close(fd[0]);
        string streamUrl = r->get_stream_url();
        write(fd[1], streamUrl.c_str(), sizeof streamUrl);
    }
}

srs_error_t SrsObjectDetection::do_object_detection(string streamUrl) {
    srs_trace("do object detection: %s", streamUrl.c_str());
    Mat src;
    float scaling_factor = 0.5;
    VideoCapture capture(streamUrl);
    if (!capture.isOpened()) {
        return srs_error_new(ERROR_OPENCV_OPEN_STREAM, "opencv videocapture open stream failed");
    }
    srs_trace("opencv videocapture open stream success");

    capture >> src;
    VideoWriter writer;
    // select desired codec (must be available at runtime)
    int codec = VideoWriter::fourcc('M', 'J', 'P', 'G');
    // framerate of the created video stream
    // double fps = 25.0;
    double fps = capture.get(CAP_PROP_FPS);
    srs_trace("the published stream fps is %f", fps);

    // name of the output video file
    uuid_t file_name;
    uuid_generate_time(file_name);
    string file_name_str((char*)file_name);
    string filename = "../../object_detection/" + file_name_str + ".avi";

    bool isColor = (src.type() == CV_8UC3);
    writer.open(filename, codec, fps, src.size(), isColor);
    // check if we succeeded
    if (!writer.isOpened()) {
        return srs_error_new(ERROR_OPENCV_OPEN_WRITER, "opencv could not open the output video file for write");
    }
    srs_trace("opencv open the output video file for writing success");
    while (capture.isOpened()) {
        bool ok = capture.read(src);
        if (!ok || src.empty()) {
            continue;
        }
        // Mat dst;
        // resize(src, dst, Size(), scaling_factor, scaling_factor, INTER_AREA);
        writer.write(src);
    }
    capture.release();
}