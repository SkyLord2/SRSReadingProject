//
// Created by cds on 22-9-11.
//

#ifndef SRS_APP_OBJECT_DETECTION_HPP
#define SRS_APP_OBJECT_DETECTION_HPP

#include <srs_core.hpp>
#include <srs_rtmp_stack.hpp>

class SrsObjectDetection {
public:
    SrsObjectDetection();
    ~SrsObjectDetection();

public:
    srs_error_t on_publish(SrsRequest* r);
    srs_error_t do_object_detection(std::string streamUrl);
};
#endif //SRS_APP_OBJECT_DETECTION_HPP
