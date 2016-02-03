/*
 * pid.c
 *
 *  Created on: 04.03.2015
 *      Author: Vrayo Systems Ltd. team
 *      issue #635
 */

/**
 *
 * @param error - current error
 * @param lastError - don't touch
 * @param output - init as current output value
 * @param ITerm - init as ITerm = output and dont touch
 * @param Kp - pid paramet
 * @param Ki - ---//---
 * @param Kd - ---//---
 */
void computePID(float error, float *lastError, float *output, float *ITerm, float Kp, float Ki, float Kd) {
    /*Compute all the working error variables*/
    *ITerm += (Ki * error);

    double dInput = (*lastError - error);
    /*Compute PID Output*/
    *output = Kp * error + *ITerm - Kd * dInput;

    *lastError = error;
}

