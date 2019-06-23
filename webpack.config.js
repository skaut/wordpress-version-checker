const path = require('path');

module.exports = {
	mode: 'development',
	entry: {
		index: './src/index.ts'
	},
	module: {
		rules: [
			{
				test: /\.ts$/,
				loader: 'ts-loader',
				exclude: /node_modules/
			},
		]
	},
	resolve: {
		extensions: ['.ts', '.js']
	},
	output: {
		filename: '[name].js',
		path: path.resolve(__dirname, 'lib')
	}
};
