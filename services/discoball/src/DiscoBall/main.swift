import Foundation
import COpenGL
import CFreeGLUT

func initGL() {
	glEnable(UInt32(GL_DEPTH_TEST))
	glEnable(UInt32(GL_ALPHA_TEST))
	glEnable(UInt32(GL_LIGHTING))
	glEnable(UInt32(GL_COLOR_MATERIAL))
	// glEnable(UInt32(GL_TEXTURE_2D))
	glDepthFunc(UInt32(GL_LEQUAL))
	// glCullFace(UInt32(GL_BACK))
	// glFrontFace(UInt32(GL_CCW))
	glEnable(UInt32(GL_CULL_FACE))
	glEnable(UInt32(GL_BLEND))
	glBlendFunc(UInt32(GL_SRC_ALPHA), UInt32(GL_ONE_MINUS_SRC_ALPHA));
	glEnable(UInt32(GL_NORMALIZE));
	glShadeModel(UInt32(GL_SMOOTH))
	glLightModelf(UInt32(GL_LIGHT_MODEL_TWO_SIDE), GLfloat(GL_TRUE));
	glHint(UInt32(GL_PERSPECTIVE_CORRECTION_HINT), UInt32(GL_NICEST))
}

let N = 100
let M = 50

let takeEvery = 50
var lastTake: Int64 = Int64.min / 2

var flashTime: Int64 = Int64.min / 2
let flashDuration = 100

let PI = 3.14159265359

func rotateX(_ x:GLdouble, _ y:GLdouble, _ z:GLdouble, angle: Double) -> (x:GLdouble, y:GLdouble, z:GLdouble) {
	let new_x = x 
	let new_y = y * GLdouble(cos(angle)) - y * GLdouble(sin(angle))
	let new_z = z * GLdouble(sin(angle)) + y * GLdouble(cos(angle))

	return (new_x, new_y, new_z)
}


func rotateY(_ x:GLdouble, _ y:GLdouble, _ z:GLdouble, angle: Double) -> (x:GLdouble, y:GLdouble, z:GLdouble) {
	let new_x = x * GLdouble(cos(angle)) + z * GLdouble(sin(angle))
	let new_y = y
	let new_z = -x * GLdouble(sin(angle)) + z * GLdouble(cos(angle))

	return (new_x, new_y, new_z)
}

func rotateZ(_ x:GLdouble, _ y:GLdouble, _ z:GLdouble, angle: Double) -> (x:GLdouble, y:GLdouble, z:GLdouble) {
	let new_x = x * GLdouble(cos(angle)) - y * GLdouble(sin(angle))
	let new_y = x * GLdouble(sin(angle)) + y * GLdouble(cos(angle))
	let new_z = z

	return (new_x, new_y, new_z)
}

var colors : [(Float, Float, Float)] = []

func randomFloat() -> Float{
	return Float(random())/Float(2147483648)
}

func regenColors() {
	colors = []
	for y in 0..<M {
		let yRatio = Float(y) / Float(M)
		let norm_Y = (1 + sin(yRatio * 2 * Float(PI))) / 2

		for x in 0..<N {
			let xRatio = Float(x) / Float(N)
			let norm_X = (1 + cos(xRatio * 2 * Float(PI))) / 2

			let red = 0.5 + norm_X / 2 / 2 + (0.25 - norm_Y / 2 / 2) + randomFloat() / 10
			let green = 0.5 + (0.25 - norm_Y / 2 / 2) + randomFloat() / 10
			let blue = 0.5 + norm_X / 2 - (0.25 - norm_Y / 2 / 2) + randomFloat() / 10
			colors.append((red, green , blue))
		}
	}

}

regenColors()
var time: Int64 = 0

var specials: [[Bool]] = []

for column in 0..<M {
    specials.append(Array(repeating:false, count:N))
}

func printOnBall(_ text: String, posY: Int = M / 2 - 10) {
	var posX = N / 2

	for character in text.characters {
		let char = characterToFont(character)

		for (y, row) in char.enumerated() {
			for(x, val) in row.enumerated() {
				specials[M - 1 - (y + posY)][(x + posX) % N] = val
			}
			specials[M - 1 - (y + posY)][(char[0].count + posX) % N] = false
		}
		posX += char[0].count + 1
	}	
}

var fileDesc: Int32 = -1


let buf_N = 200
var buf: [UInt8] = Array(repeating:0x00, count:buf_N)
var bufPos = 0

func readRest() {
	var b: UInt8 = 0
	repeat {} while read(fileDesc, &b, 1) !=  -1
}


extension String {
	func substr(_ start: Int, _ end: Int) -> String{
		return self.substringWithRange(Range<String.Index>(self.startIndex.advanced(by: start)..<self.startIndex.advanced(by:end)))
	}
}

func pad(string : String, toSize: Int) -> String {
    var padded = string
    for _ in 0..<toSize - string.characters.count {
        padded = "0" + padded
    }
    return padded
}

let tbl = [
	"11110": "0000",
	"01001": "0001",
	"10100": "0010",
	"10101": "0011",
	"01010": "0100",
	"01011": "0101",
	"01110": "0110",
	"01111": "0111",
	"10010": "1000",
	"10011": "1001",
	"10110": "1010",
	"10111": "1011",
	"11010": "1100",
	"11011": "1101",
	"11100": "1110",
	"11101": "1111"
]

func decode(_ buf: [UInt8]) -> String {
	var octets = buf.map {pad(string: String($0, radix: 2), toSize: 8)}
	var conv = octets.joined(separator:"")
	var bits = [String](conv.characters.map {String($0)})

	for _ in 0..<8 {
		var ansArray: [String] = []

		for i in 0..<bits.count / 5 {
			var s: String = bits[i * 5]
			s += bits[i * 5 + 1]
			s += bits[i * 5 + 2]
			s += bits[i * 5 + 3]
			s += bits[i * 5 + 4]
			
			if let val = tbl[s] {
				ansArray.append(val)
			}
		}
		var ans = ansArray.joined(separator:"")

		var stringResultArray: [String] = []
		for i in 0..<ans.characters.count / 8 {
			let number = strtoul(ans.substr(i * 8, i * 8 + 8), nil, 2)
			stringResultArray.append(String(UnicodeScalar(Int(number))))
		}

		let stringResult = stringResultArray.joined(separator:"")
		print(stringResult)

		if let range = stringResult.rangeOfString("FLAG") {
			let ret = stringResult.substringWithRange(range.startIndex..<range.startIndex.advanced(by:40, limit:stringResult.endIndex))
			let ret = stringResult[range.startIndex:range.startIndex+40]
		}

		bits.insert("0", at: 0)
	}

	return ""

}

decode([0b11110111, 0b10111101])

func renderFunction() {
	if fileDesc == -1 {
		var err: Int32 = 2
		for i in 0...0 {
			fileDesc = open( "/dev/ttyUSB\(i)", O_RDONLY | O_NONBLOCK | O_NDELAY );
			// fileDesc = open( "/dev/ttyUSB\(i)", O_RDONLY );

			if fileDesc != -1 {
				var tty: termios = termios()
				tcgetattr ( fileDesc, &tty )
				cfsetospeed (&tty, UInt32(B9600));
				cfsetispeed (&tty, UInt32(B9600));

				tty.c_cflag     &=  ~UInt32(PARENB)        // Make 8n1
				// tty.c_cflag     |=  UInt32(PARENB)        // Make 8n1
				tty.c_cflag     &=  ~UInt32(CSTOPB)
				tty.c_cflag     &=  ~UInt32(CSIZE)
				tty.c_cflag     |=  UInt32(CS8)
				tty.c_cflag     &=  ~UInt32(CRTSCTS);       // no flow control
				tty.c_lflag     =   0;          // no signaling chars, no echo, no canonical processing
				tty.c_oflag     =   0;                  // no remapping, no delays
				tty.c_cc.6      =   0;                  // read doesn't block
				tty.c_cc.5      =   5;                  // 0.5 seconds read timeout
				
				tty.c_cflag     |=  UInt32(CREAD) | UInt32(CLOCAL);     // turn on READ & ignore ctrl lines
				tty.c_iflag     &=  ~(UInt32(IXON) | UInt32(IXOFF) | UInt32(IXANY));// turn off s/w flow ctrl
				tty.c_lflag     &=  ~(UInt32(ICANON) | UInt32(ECHO) | UInt32(ECHOE) | UInt32(ISIG)); // make raw
				tty.c_oflag     &=  ~UInt32(OPOST);              // make raw

				tcflush( fileDesc, TCIFLUSH )
				tcsetattr ( fileDesc, TCSANOW, &tty ) 

				break
			}

			if errno != 2 {
				err = errno
			}
		}

		if fileDesc == -1 {
			if err == 2 {
				printOnBall("No device")
			} else if err == 13 {
				printOnBall("No access")
			}
		} else {

			printOnBall("OK")
		}
	}


	if time - lastTake > takeEvery {
		var b: UInt8 = 0
		let n = read(fileDesc, &b, 1)
		if n == -1 && errno == 11 {
		} else if n == -1 {
			fileDesc = -1
		} else if n == 1 {
			buf[bufPos] = b
			bufPos = bufPos + 1
			if bufPos == buf_N {
				bufPos = 0

				var s: String = ""

				for i in 0..<buf_N {
					s += String(UnicodeScalar(Int(buf[i])))
				}

				var decoded = decode(buf)

				if decoded.characters.count > 3 {
					printOnBall(decoded)
					flashTime = time
				}

				readRest()
				lastTake = time
			}
		}
	}


    if (time - flashTime) < flashDuration {
    	let grad = 1.0 - cos(Float(PI / 2) *  Float(time - flashTime) / Float(flashDuration))
	    glClearColor(grad, 1.0, 1.0, 0.0)

    } else {
	    glClearColor(1.0, 1.0, 1.0, 0.0)
    }

    glClearDepth(1.0)

    glClear(UInt32(GL_COLOR_BUFFER_BIT) | UInt32(GL_DEPTH_BUFFER_BIT))
	glMatrixMode(UInt32(GL_MODELVIEW))
	glLoadIdentity()

	let ambient: [GLfloat] = [0.3, 0.3, 0.3, 1]
	glLightModelfv(UInt32(GL_LIGHT_MODEL_AMBIENT), ambient)

	glColorMaterial(UInt32(GL_FRONT_AND_BACK), UInt32(GL_AMBIENT_AND_DIFFUSE))

    glEnable(UInt32(GL_LIGHT0))
    glLightfv(UInt32(GL_LIGHT0), UInt32(GL_DIFFUSE), [1, 1, 1]);
    glLightfv(UInt32(GL_LIGHT0), UInt32(GL_SPECULAR), [1, 1, 1]);
    glLightfv(UInt32(GL_LIGHT0), UInt32(GL_POSITION), [5.0, 2.0, 5.0, 0.0]);
    glLightfv(UInt32(GL_LIGHT0), UInt32(GL_SPOT_DIRECTION), [0.0, 0.0, -1.0, 0.0]);
	glLightf(UInt32(GL_LIGHT0), UInt32(GL_CONSTANT_ATTENUATION), 0.0);
    glLightf(UInt32(GL_LIGHT0), UInt32(GL_LINEAR_ATTENUATION), 0.2);
    glLightf(UInt32(GL_LIGHT0), UInt32(GL_QUADRATIC_ATTENUATION), 0.4);

    glLoadIdentity(); 
	glTranslatef(0, -0.3, -3.5);

	glRotated(15, 1.0, 0.0, 0.0);
	// glRotatef(sin(Float(time % 2500) / 2500 * 2 * Float(PI)) * 100 , 0.0, 1.0, 0.0);
	glRotatef(sin(Float(time % 2500) / 2500 * 2 * Float(PI)) * 200 , 0.0, 1.0, 0.0);
	glMaterialfv(UInt32(GL_FRONT_AND_BACK), UInt32(GL_SPECULAR), [GLfloat]([-0.100, -0.100, -0.100, 1.000]))

    glBegin(UInt32(GL_QUADS))	
	    for vert in 0 ..< (M - 1) { 
		    let ang_v = -PI/2 + (PI / Double(M)) * Double(vert)
		    let ang_v_next = -PI/2 + (PI / Double(M)) * Double((vert + 1) % M) + 0.0005

	    	let (x, y, z) : (GLdouble, GLdouble, GLdouble) = (1.0, 0.0, 0.0)

	    	let p_pre1 = rotateZ(x, y, z, angle:ang_v)
	    	let p_pre2 = vert + 1 + 1 != M ? rotateZ(x, y, z, angle:ang_v_next) : (x: 0.0, y: 1.0, z:0.0)

	    	let ang_offset = Double(vert % 3) * 0.006

		    for hor in 0 ..< N {
		    	if specials[vert][hor] {
		    		let helper1 = (sin(Float(time + N * 20) % 100 / 100 * 2 * Float(PI)) + 1 / 2) * 0.2
	    			glMaterialfv(UInt32(GL_FRONT), UInt32(GL_EMISSION), [GLfloat]([0.4 + helper1, 0.4 + helper1, 0.4 + helper1, 1.0]))
	    			// glMaterialfv(UInt32(GL_FRONT), UInt32(GL_EMISSION), [GLfloat]([0.4, 0.4, 0.4, 1.0]))
		    	} else {
	    			glMaterialfv(UInt32(GL_FRONT), UInt32(GL_EMISSION), [GLfloat]([0.0, 0.0, 0.0, 1.0]))
		    	}

		    	let ang_h = (2 * PI / Double(N)) * Double(hor) + ang_offset
		    	let ang_h_next = (2 * PI / Double(N)) * Double((hor + 1) % N) + ang_offset

				let p1 = rotateY(p_pre1.x, p_pre1.y, p_pre1.z, angle:ang_h)
				let p2 = rotateY(p_pre1.x, p_pre1.y, p_pre1.z, angle:ang_h_next)

				let p3 = rotateY(p_pre2.x, p_pre2.y, p_pre2.z, angle:ang_h)
				let p4 = rotateY(p_pre2.x, p_pre2.y, p_pre2.z, angle:ang_h_next)

				let c = colors[vert * N + hor]

				glColor4f(c.0, c.1, c.2, 1.0)

		        glNormal3d (p1.x, p1.y, p1.z)

		        glVertex3d( p1.x, p1.y, p1.z);
		        glVertex3d( p2.x, p2.y, p2.z);
		        glVertex3d( p4.x, p4.y, p4.z);
		        glVertex3d( p3.x, p3.y, p3.z);

	    	}
		}
    glEnd()

	glLineWidth(2.5); 
	glBegin(UInt32(GL_LINES))
	glColor3f(1.25, 1.25, 1.25)
	glVertex3f(0.0, 1.0, 0.0)
	glVertex3f(0.0, 5.0, 0.0)
	glEnd()

	glLoadIdentity()

    glFlush()
    glutSwapBuffers()

    time += 1

    // N = 50 + Int(time) / 200
    // if time % 1 == 0{
    	// regenColors()
    	// let (y,x) = (y: random() % M, x: random() % N)
    	// specials[y][x] = !specials[y][x]
    // }
}

func reshape(width: GLsizei, height: GLsizei) {
	let w = width
	var h = height
   	if height == 0 {
   		h = 1
   	}
   	let aspect: GLdouble = GLdouble(w) / GLdouble(h)
 
    glViewport(0, 0, w, h)
 
    glMatrixMode(UInt32(GL_PROJECTION))  // To operate on the Projection matrix
    glLoadIdentity()             // Reset
    gluPerspective(45.0, aspect, 0.1, 100.0)
}

func timer(value: Int32) {
	glutPostRedisplay()
	glutTimerFunc(15, timer, 0)
}


var localArgc = Process.argc
glutInit(&localArgc, Process.unsafeArgv)
glutInitDisplayMode(UInt32(GLUT_DOUBLE))
glutInitWindowSize(640,480)
glutInitWindowPosition(100,100)
glutCreateWindow("DiscoBall")
initGL()
glutDisplayFunc(renderFunction)
glutReshapeFunc(reshape)
glutTimerFunc(0, timer, 0);
glutMainLoop()
