/*
 * pid.c
 *
 *  Created on: 04.03.2015
 *      Author: Kuznetsov Andrey
 *      issue #635
 */


void computePID(float error, float *lastError, float *output, float *ITerm, float Kp, float Ki, float Kd) {
    /*Compute all the working error variables*/
    *ITerm += (Ki * error);

    double dInput = (lastError - error);
    /*Compute PID Output*/
    *output = Kp * error + *ITerm - Kd * dInput;

    *lastError = error;
}

