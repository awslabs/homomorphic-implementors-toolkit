// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "matrix.h"

using namespace std;

// create a matrix where each column is the input vector
Matrix rowVecToMatrix(const vector<double> &x, int width) {
  vector<double> y;
  y.reserve(width*x.size());
  for(int i = 0; i < x.size(); i++) {
    for(int j = 0; j < width; j++) {
      y.push_back(x[i]);
    }
  }
  Matrix temp(x.size(), width);
  temp.data() = y;
  return temp;
}

// create a matrix where each row is the input vector
Matrix colVecToMatrix(const vector<double> &x, int height) {
  vector<double> y;
  y.reserve(height*x.size());
  for(int i = 0; i < height; i++) {
    for(int j = 0; j < x.size(); j++) {
      y.push_back(x[j]);
    }
  }
  Matrix temp(height, x.size());
  temp.data() = y;
  return temp;
}

Matrix matrixRowConcat(const vector<Matrix> xs) {
  if(xs.size() == 0) {
    throw invalid_argument("matrixRowConcat: xs cannot be empty");
  }
  int h = xs[0].size1();

  int totalWidth = xs[0].size2();
  for(int i = 1; i < xs.size(); i++) {
    totalWidth += xs[i].size2();
    if(xs[i].size1() != h) {
      throw invalid_argument("matrixRowConcat: all xs must have the same height");
    }
  }

  vector<double> cmatdata;
  for(int row = 0; row < h; row++) {
    for(int i = 0; i < xs.size(); i++) {
      int w = xs[i].size2();
      for(int col = 0; col < w; col++) {
        cmatdata.push_back(xs[i].data()[row*w+col]);
      }
    }
  }
  Matrix temp(h, totalWidth);
  temp.data() = cmatdata;
  return temp;
}

Matrix hadamard_prod(const Matrix &a, const Matrix &b) {
  if(a.size1() != b.size1()) {
    throw invalid_argument("hadamard_prod: height mismatch");
  }
  if(a.size2() != b.size2()) {
    throw invalid_argument("hadamard_prod: width mismatch");
  }
  if(a.data().size() != b.data().size()) {
    throw invalid_argument("hadamard_prod: data size mismatch");
  }

  vector<double> result;

  for(int i = 0; i < a.data().size(); i++) {
    result.push_back(a.data()[i] * b.data()[i]);
  }
  Matrix temp(a.size1(), a.size2());
  temp.data() = result;
  return temp;
}

Vector fromStdVector(const vector<double> &v) {
  Vector temp(v.size());
  temp.data() = v;
  return temp;
}
