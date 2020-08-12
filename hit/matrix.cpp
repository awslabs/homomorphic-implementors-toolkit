// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "matrix.h"

// create a matrix where each column is the input vector
Matrix rowVecToMatrix(const std::vector<double> &x, int width) {
  std::vector<double> y;
  y.reserve(width*x.size());
  for(double value : x) {
    for(int j = 0; j < width; j++) {
      y.push_back(value);
    }
  }
  Matrix temp(x.size(), width);
  temp.data() = y;
  return temp;
}

// create a matrix where each row is the input std::vector
Matrix colVecToMatrix(const std::vector<double> &x, int height) {
  std::vector<double> y;
  y.reserve(height*x.size());
  for(int i = 0; i < height; i++) {
    for(double v : x) {
      y.push_back(v);
    }
  }
  Matrix temp(height, x.size());
  temp.data() = y;
  return temp;
}

Matrix matrixRowConcat(const std::vector<Matrix> &xs) {
  if(xs.empty()) {
    throw std::invalid_argument("matrixRowConcat: xs cannot be empty");
  }
  int h = xs[0].size1();

  int totalWidth = xs[0].size2();
  for(int i = 1; i < xs.size(); i++) {
    totalWidth += xs[i].size2();
    if(xs[i].size1() != h) {
      throw std::invalid_argument("matrixRowConcat: all xs must have the same height");
    }
  }

  std::vector<double> cmatdata;
  for(int row = 0; row < h; row++) {
    for(const auto &x : xs) {
      int w = x.size2();
      for(int col = 0; col < w; col++) {
        cmatdata.push_back(x.data()[row*w+col]);
      }
    }
  }
  Matrix temp(h, totalWidth);
  temp.data() = cmatdata;
  return temp;
}

Matrix hadamard_prod(const Matrix &a, const Matrix &b) {
  if(a.size1() != b.size1()) {
    throw std::invalid_argument("hadamard_prod: height mismatch");
  }
  if(a.size2() != b.size2()) {
    throw std::invalid_argument("hadamard_prod: width mismatch");
  }
  if(a.data().size() != b.data().size()) {
    throw std::invalid_argument("hadamard_prod: data size mismatch");
  }

  std::vector<double> result;
  result.reserve(a.data().size());
  for(int i = 0; i < a.data().size(); i++) {
    result.push_back(a.data()[i] * b.data()[i]);
  }
  Matrix temp(a.size1(), a.size2());
  temp.data() = result;
  return temp;
}

Vector fromStdVector(const std::vector<double> &v) {
  Vector temp(v.size());
  temp.data() = v;
  return temp;
}
