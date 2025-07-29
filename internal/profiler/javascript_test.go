package profiler

import (
	"reflect"
	"testing"
)

func TestSplitIntoStatements(t *testing.T) {
	tests := []struct {
		name string
		js   string
		want []string
	}{
		{
			name: "Simple statements",
			js:   "var x = 1; var y = 2;",
			want: []string{"var x = 1;", "var y = 2;"},
		},
		{
			name: "Statements with strings containing semicolons",
			js:   "var x = 'test;'; var y = \"also;test\";",
			want: []string{"var x = 'test;';", "var y = \"also;test\";"},
		},
		{
			name: "Statement without trailing semicolon",
			js:   "var x = 1; var y = 2",
			want: []string{"var x = 1;", "var y = 2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitIntoStatements(tt.js)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitIntoStatements() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPropertyPathExtraction(t *testing.T) {
	testCases := []struct {
		name string
		js   string
		paths map[string]string
	}{
		{
			name: "Simple property path",
			js:   "angular.version = '1.8.2';",
			paths: map[string]string{
				"angular.version": "1.8.2",
			},
		},
		{
			name: "Nested property path",
			js:   "Vue.config.devtools = true;",
			paths: map[string]string{
				"Vue.config.devtools": "true",
			},
		},
		{
			name: "Property path with numeric values",
			js:   "app.version = 2.3;",
			paths: map[string]string{
				"app.version": "2.3",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractJSGlobals(tc.js)
			
			for path, expectedValue := range tc.paths {
				if value, exists := result.PropertyPaths[path]; !exists {
					t.Errorf("Failed to extract property path: %s", path)
				} else if value != expectedValue && value != "" {
					t.Errorf("Property path %s has value %s, expected %s", path, value, expectedValue)
				}
			}
		})
	}
}

func TestLibraryDetection(t *testing.T) {
	testCases := []struct {
		name string
		js   string
		libs []string
	}{
		{
			name: "jQuery detection",
			js:   "jQuery.fn.jquery = '3.6.0';",
			libs: []string{"jQuery"},
		},
		{
			name: "Angular detection",
			js:   "angular.module('myApp', []);",
			libs: []string{"AngularJS"},
		},
		{
			name: "React detection",
			js:   "React.version = '16.0.0'; React.createElement('div', null, 'Hello');",
			libs: []string{"React"},
		},
		{
			name: "Lodash detection",
			js:   "_.map([1, 2, 3], function(n) { return n * 2; });",
			libs: []string{"Lodash"},
		},
		{
			name: "Multiple libraries",
			js:   "jQuery.fn.jquery = '3.6.0'; angular.module('myApp', []); React.version = '17.0.2';",
			libs: []string{"jQuery", "AngularJS", "React"},
		},
		{
			name: "Library with complex formatting",
			js:   "/* Comments before */ \n  jQuery.fn.jquery = \n  '3.6.0' // Comments after",
			libs: []string{"jQuery"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractJSGlobals(tc.js)
			
			for _, lib := range tc.libs {
				if _, exists := result.DetectedLibraries[lib]; !exists {
					t.Errorf("Failed to detect library: %s", lib)
				}
			}
		})
	}
}