/*
 * pid.h
 *
 *  Created on: 04.03.2015
 *      Author: Vrayo Systems Ltd. team
 */

#ifndef PID_H_
#define PID_H_

struct PIDstruct {
    float Kp;
    float Ki;
    float Kd;
    float in;
    float out;
    int T;
};

void ComputePID(float error, float *lastError, float *output, float *ITerm, float Kp, float Ki, float Kd);

#endif /* PID_H_ */
