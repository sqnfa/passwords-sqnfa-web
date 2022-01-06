const path = require('path');

module.exports = {
  entry: './src/index.ts',
  mode: 'production',
  devtool: 'source-map',
  target: ['web', 'es5'],
  module: {
    rules: [
      {
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
    fallback: {
      crypto: false,
    },
  },
  output: {
    filename: 'passwords-sqnfa-web.min.js',
    path: path.resolve(__dirname, 'build'),
  },
};
