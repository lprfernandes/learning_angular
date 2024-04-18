# Code Compilation Process
* Application Source Code (Typescript) => TypeScript Compiler => Js Code
* Template (HTML) => Angular Compiler => Js Code

# Building Blocks of Angular
1. Component (App Data + Event Handlers) - each screen must have its component (Comparable to a Controller + View in .net)
2. Templates (Html Design Logic) - can access the data present in the component through data binding
3. Data Binding - mediates between component and templates
4. Modules - Collection of components (Comparable to an application in .net)
5. Services - Business Logic + Ajax api calls (Comparable to a Service in .net)
6. Dependency injection (Loads service objects into Components)
7. Directives (Direct DOM manipulation)

# Angular Architecture
* Component - Contains application data and logic in form of event handler methods which respond to user actions. Every component has a template. This template has html logic to describe the views. These 2 exchange information using the data binding mechanism.
* Modules - Are mainly used to group the related components
* Service - Class that contains client side business logic involved in loading the data from servers by making ajax calls to the REST API servers.
* Dependency injection - concept of creating objects at runtime automatically and loading those service objects into the constructor of the components.

# Libraries
* @angular/core - provides pre-defined decorator, classes, interfaces and modules needed to run every angular app.
* @angular/common - provides built-in directives (ngIfm ngSwitch,ngClass, etc)
* @angular/compiler - Compiles templates html code into js code
* @angular/platform-browser-dynamic - invokes angular compiler
* @angular/platform-browser - provides set of pre-defined classes related to DOM and browser interaction.
* @angular/forms - provides pre-defined classes related to angular forms.
* @angular/router - provides pre-defined classes that are needed to create and execute angular routes.
* @angular/animations - provides pre-defined classes that are needed to create and execute animations.
* @angular/cli - provides pre-defined commands that are needed to create, compile, build, etc
* @rxjs - provides pre-defined classes for creating Observables
* @zone.js - provides pre-defined change detection processes.

# App Folder Structure
* e2e - contains end to end test cases
* src - contains the source code of the app
    * app
        * app.component.scss => css styles of app component
        * app.component.html => template of app component
        * app.component.spec.ts => unit test cases of app component
        * app.component.ts => app component
        * app.module.ts => app module
        * app-routing.module.ts => routing configuration
    * assets => contains static files such as images
    * favicon.ico => contains browser icon
    * index.html => default page / startup page
    * main.ts => defines startup mode
    * polyfills.ts => defines polyfills (additional scripts) needed to load & run app
    * styles.scss => global css styles of entire app
* angular.json => contains angular cli configuration
* package.json => current app packages
* tsconfig.json => ts compiler config settings

# Create new project

    ng new MyApplication --style=scss --routing --standalone=false

This will create a new project structure called MyApplication with scss style with routing activated.
To execute the application:

    ng serve 

Optionally if we want to open the browser automatically

    ng serve --open

Optionally if we want to specify a port

    ng serve --open --port=5200


## Flow of execution

Index.html => main.ts => app.module.ts => app.component.ts + app.component.html 

## Angular.json config

Add the following packages

    npm install jquery popper.js bootstrap@4 font-awesome --save
    
And on the architect part of the angular.json add:
(Attention, it's the first block, close to build)

    "styles": [
        "src/styles.scss",
        "node_modules/bootstrap/dist/css/bootstrap.css",
        "node_modules/font-awesome/css/font-awesome.css"
    ],
    "scripts": [
        "node_modules/jquery/dist/jquery.js",
        "node_modules/popper.js/dist/umd/popper.js",
        "node_modules/bootstrap/dist/js/bootstrap.js"
    ]

# Components
It's a class that contains the app data and event handler methods.
For every screen we're required to create a component

    @Component({
        //metadata of the component
        templateUrl: "template.html" //associating the component to the template
        selector: "tagName", // calling the template inside the html <tagName></tagName>
        styleUrls: ["StyleSheet.css"]

    })
    class Component 
    {
        Properties
        Methods
    }


    ng g class MyClass

Each component has its own template. These contain design logic in html to render the output.
It can access all the props and event handler methods of the corresponding component.
A component can call other component through it's template.

## Creating a component
On a terminal we add this command: 

    ng g component myComponent

This will create a subfolder in the app folder with the name specified in the command
For every component 4 files will be created:

    ...component.html //template
    ...component.spec.ts //unit test cases
    ...component.ts //actual component definition
    ...component.scss //stylesheet

The component declaration is added to the app.module.ts file

## Component Hierarchy

Root Component (App Component)
    Child1 Component
        Grandchild1 Component
    Child2 Component
        Grandchild2 Component
    

# Routing
Allows us to load components based on the url changes. (Single-Page-Application)
A route maps an url to a component.

1. Download the @angular/router package
2. Define base url in index.html file // <base href="/">
3. Create hyperlink for each route // <a routerLink="path"> Link Text</a>
(from angular 17 forward, in standalone module, create an import statement and then on the module imports as well.)
4. Create Router Module (app-routing-module.ts) and inside the const routes and the class AppRoutingModule. Add a route for the empty string, because the landing page doesn't match any path. Then redirect to any other page. // {path:"", redirectTo: "dashboard", pathMatch:"full"}
5. Create Router Outlet tag in app.component.html //<router-outlet></router-outlet> , to represent where the component must be reflected, generally inside a div with container-fluid class of bootstrap

# HTML Component inline logic operations
## ngFor
Reads data from an array and executes a template for each item in the array

    <tag *ngFor="let varName of arrayName">
    </tag>

So instead of:

    <div class="dropdown-menu">
    <a class="dropdown-item" href="#">Project A</a>
    <a class="dropdown-item" href="#">Project B</a>
    <a class="dropdown-item" href="#">Project C</a>
    <a class="dropdown-item" href="#">Project D</a>
    </div>

We have:

    <div class="dropdown-menu">
    <a class="dropdown-item" href="#" *ngFor="let project of Projects">{{project}}</a>
    </div>

## Making an Attribute dynamic
We add the [attr. ] around the attribute to make it dynamic. In this case we want to add an i which is the index of the previous loop.

    <div class="card" *ngFor="let teamMembersGroup of TeamMembers; let i = index">
        [attr.data-target]="'#cardbody' + i"


## Data Bindings
Relation between the template and the component.

* Interpolation Binding {{}} - used to display a value
* Property Binding [] - used to assign a value of one property to another property
* Event Binding () - used to call a method when a user performs an action
* Two-way Binding [()] - used to read a value of a prop and display it and then when the user changes that value and we want to revert that change to the prop


## Handle Dynamic Style & ngClass
We can change the css style properties of a tag like so:

    td<[style.property] = "value"
    or
    td<[style.property] = "(condition)? truevalue : falsevalue"

We can change a class of a tag like so:

    td<[ngClass] = "value"
    td<[ngClass] = "(condition)? truevalue : falsevalue"

## If / If-else / Template

    <td *ngIf="condition"></td>
    
    <td *ngIf="condition; then TrueTemplate; else FalseTemplate"></td>

    <ng-template #TrueTemplate>
        <div>...
    </ng-template>
        
    <ng-template #FalseTemplate>
        <div>...
    </ng-template>


## Built-in Pipes
Pipe is as class that receives a value, executes a function transform and returns the value that is to be printed in the output.

{{user | uppercase}}
{{designation | lowercase}}
{{property | slice : startIndex : endIndex}}
{{value | number : .2}} //provides digit grouping and controls decimal places
{{productPrice | currency : "USD"}}
{{property | percent }}
{{property | json }}
{{property | date }} //check date formats of pipe date
{{property | date : "shortDate" }} 

## ngSwitch

    <div [ngSwitch] = "property">
        <div *ngSwitchCase="'value1'"> Content 1</div>
        <div *ngSwitchCase="'value2'"> Content 2</div>
        <div *ngSwitchCase="'value3'"> Content 3</div>
        <div *ngSwitchDefault> Content Default</div>
    </div>



# Modules
Collection of components, directives and pipes. It's used mainly to organize and consolidate them and make them public and usable across the app. (ex Login module)

To create it, on the terminal:

    ng g module Admin

This will create a folder with the module name and inside the module.ts file where the class is exported and decorated with the @NgModule tag

    @NgModule({ //module metadata
        declarations:[...,...,...],
        exports:[...,...,...],
        imports:[...,...,...],
        providers: [...,...,...]
    })
    class ModuleName
    {        
    }

* declarations - list of components, directives and pipes, that are part of current module
* exports - list of components that are public and are being made accessible to other modules.
* imports - list of modules that the current module imports.
* providers - list of services that can be used in the current module.

## Standalone Components
Now with Angular there's the concept of standalone components, meaning that there is no need to create an ngModule first.

# Services
Class that is a collection of props and methods which mainly contain business logic and/or data accessing and interaction.
We shouldn't access directly db's. For that we use services with Ajax (async js and xml) calls.
Services are accessible from components, directives, pipes or other services.
They don't contain event handler methods.
Their main goal is to decouple the business logic to the data access.

1. Create the service class
2. Make ready the service for dependency injection

    @Injectable({
    providedIn: ""
    })
    class Component{
    }

3. Provide the service globally/locally by 1 one the following ways:

* Add the "root" keyword to the providedIn prop of the injectable decorator like so (globally and on a singleton):

    @Injectable({
    providedIn: "root"
    })
    class Component{
    }

* Add the service to the app.module providers metadata (globally and on a singleton as well)

* Add the service in child modules providers metadata (local accessible to those specific modules)

* Inject directly the service in the providers of the components metadata (local accessible to those specific components)

4. Inject the service into actual component.

    class Component
    {
        constructor(@Inject(Service) private service: Service)
        {
        }
    } 

To create from terminal:

    ng g service MyService

<br><br>

# Observables and Observers RxJS
Its a pattern of message passing from publisher to subscriber

1. Observable is created
2. Observer subscribes to the observable
3. Observable can pass notifications to the observer

An Observable has 3 functions
* Handle data - when data is sent from the observable to the observer
* Handle error - executes only once in case of error
* Handle completion - executes only once in case of success


# AJAX
## Get request

!Create everything to get from a api from scratch

1. Create a Service

    ng g service Projects

On projects.service.ts we import the HttpClient from @angular/common/http, and inject it on the ctor like so:

    constructor(private httpClient : HttpClient){
    }

Then, using this service we can make a method that will make the get, like so:

    getAllProjects() : Observable<Project[]>{
        return this.httpClient.get<Project[]>("/api/projects");
    }

Finally, we add the HttpClientModule to the app.module.ts

2. Create a Model to serve as DTO

    ng g class Project

Here we create the model with the same properties as it will be received in the json.Ex:

    export class Project
    {
        projectId: number;
        projectName: string;
        dateOfStart: string; //has to be string otherwise angular doesn't parse it!?
        teamSize : string;
    }

    constructor(){
        this.projectId = 0;
        this.projectName = "";
        this.dateOfStart = null;
        this.teamSize = 0;
    }

3. To call the service we need a component:

    ng g component Projects

In there, we import the service we created and then inject it on the component ctor, like so:

    projects: Project[] = [];

    constructor(private projectsService: ProjectsService){

    }

    ngOnInit(){
        this.projectsService.getAllProjects().subscribe(
            (response: Project[]) => {
                this.projects = response;
            }
        );
    }

4. No on the projects.component.html we can add the view that will show the values retrieved by the get:

        <h1>Projects</h1>
        <div class="row">
            <div class="col-8 mx-auto">
                <table class="table">
                    <thead>
                        <th>Project Id</th>
                        <th>Project Name</th>
                        <th>Date of Start</th>
                        <th>Team Size</th>
                    </thead>
                    <tbody>
                        <tr *ngFor="let project of projects">
                            <td>{{project.projectId}}</td>
                            <td>{{project.projectName}}</td>
                            <td>{{project.dateOfStart}}</td>
                            <td>{{project.teamSize}}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

5. Now if we want to, we can generate the dist files to add to a .net build.
To build the angular app to the dist folder we use:

    ng build

    or in dev env:
    ng build -c development

Then we copy those files to the wwwroot folder of the .net app. Now copy the contents of the newly pasted file index.html to the index view in the .net app.

# Map
Is an operator which executes a function after receiving a response from the server
first we must import the map function

    import { map } from "rxjs/operators"

    getAllProjects() : Observable<Project[]>{
    return this.httpClient.get<Project[]>("/api/projects", {responseType:"json"})
    .pipe(map(
      (data: Project[]) => {
        for( var i = 0; i < data.length; i++)
        {
          data[i].teamSize = data[i].teamSize *100;
        }
        return data;
      }
    ));
  }

## Json-server
It's a package that simulates the crud operations with a json file.
To install:

    npm install json-server -g

Create a folder data and a json file there. In the json create a list of objects of your choice. cd into data folder and add the command:

    json-server database.json --watch

Leave it open and minimized in the background. After that we get a localhost and a port to which we should direct our requests.

<br><br>

# Authentication JWT

1. User logs in, an unique jwt token is generated on the server and sent to the browser as part of a response header.
2. The browser stores it in session storage and sends it in the next requests.

## JWT Contents

1. Header (base64 string) contains type and algo

    {
        "typ":"JWT"
        "alg":"HS256"
    }

2. Payload (base64 string) contains non-sensitive user details

    {
        "userId":"xxxxxx"
    }


3. Signature (base64 string) contains the data hashed by the secret

## JWT Algo 
step1<br>
data = b64(header) + "." + b64(payload)
step2<br>
hashedData = hash(data, secret)
step3<br>
signature = b64(hashedData)
step4<br>
jwtToken = data + "." + signature

## JWT Verification Process

1. The server reads the JWT token from the request header
2. Separates the data and hashes it with the known secret
3. Compares the b64 signature with the one on the request 

## Best Practices

1. Don't include sensitive user info in the payload.
2. Don't include too much info in the payload because it bloats the requests and responses
3. Always enable https
4. Don't store jwts in cookies since they are accessible by possible attackers

## Receive header token from response and then include it in next requests

1. On the login service, in the response of the post method to the authenticate endpoint, if the user is not null we save the user object to the sessionStorage

      if (user) {
        ...
        sessionStorage\['currentUser'] = JSON.stringify(user);
      }

2. In the logout method we must remove that item

  public Logout(){
    sessionStorage.removeItem("currentUser");
    ...
  }

3. In the projects service in the get request (or any request that needs authentication):

    var currentUser = {token:""};
    var headers = new HttpHeaders();
    
    headers = headers.set("Authorization","Bearer ");

    if(sessionStorage\['currentUser'] != null){
      currentUser = JSON.parse(sessionStorage\['currentUser']);
      headers = headers.set("Authorization","Bearer " + currentUser.token);
    }

4. On the method signature we add the headers to the args:

 return this.httpClient.get<\Project[]>("/api/projects", {headers:headers,responseType:"json"})
    .pipe(map(
        ...
    ));

<br><br>

# Http Interceptors
It's a service middleware between the http client and the http backend.
Normally used to transform request and response.
They run in the sequence we add them on the module.

All the interceptors we create must implement the HttpInterceptor interface.
HttpInterceptor interface is the parent interface that handles HttpRequest class and HttpResponse class.
As in angular, the request and response are immutable, we clone, change and then send it further to the next step.

(In the following example we'll create an interceptor to include the jwt token header and its value in every request)
To create an interceptor:

    ng g service JwtInterceptor

And then on the class when we implement the HttpInterceptor interface, we must implement the intercept method:

    export class JwtInterceptorService implements HttpInterceptor{}

    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        throw new Error('Method not implemented.');
    }

(This works because every time we call a ...return this.httpClient.Post or Get, angular automatically calls the interceptor first)

And on the app module we must add it as a provider:

    providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: JwtInterceptorService,
      multi: true
    }
  ],

In this approach, all the methods with requests will be intercepted. But there is one that must not be, the first one, the "authenticate" method because it doesn't have the token yet.
To be able to exclude some and others not, we must inject in the login service 2 different httpClients, the normal httpClient which is normally intercepted and the httpBackend which is not.

export class LoginService {

  ...  
  private httpClient : HttpClient | null = null;

  constructor(private httpBackend: HttpBackend) { 
  }

    public Login(loginViewModel: LoginViewModel): Observable<any>{
        this.httpClient = new HttpClient(this.httpBackend);
        return this.httpClient.post<any>("/authenticate",loginViewModel, {responseType: "json"})
        .pipe(map(user => {...}))}}

In this way we pass the httpBackend (that doesn't have interceptors) to the httpClient and use it to make the request, not being intercepted on the way.

## Error handling Interceptors
Instead of each method having its own 401 handling logic, its best practice to do it in a centralized way with middlewares

    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        
        return next.handle(req).pipe(tap({
        next: (event: HttpEvent<any>) => {
            if (event instanceof HttpResponse) {
            //do something with response
            }
        },
        error: (error: any) => {
            if (error instanceof HttpErrorResponse) {
            if (error.status == 401) {
                console.log(error);
                alert("401 Unauthorized");
            }
            }
        } 
        } 
        ));
    }

Add the exception interceptor also the the app module providers.

    providers: [
    {
        ...
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: JwtUnauthorizedInterceptorService,
      multi: true
    }
  ]

Now remove any exception handling logic that might be present in the components.

## CanActivate Guard
Its used to check if the user is valid and if he can view the page or not.

Guard is a service class which can tell the router wether the current user can navigate to a specific route or not.
Guards execute automatically before entering to a route and before leaving the route.

CanDeactivate Guard - check whether the user can leave the current route or not, and return true or false
CanActivate Guard - check whether the user can navigate to the requested route or not, and return true or false.

1. In the project first we need to install a package:

    npm install @auth0/angular-jwt --save

2. In the app module:

    import  { JwtModule } from "@auth0/angular-jwt";

And add it to the imports with its configuration options:

    ...,
    JwtModule.forRoot({
    config: {
        tokenGetter: () => {
        return (sessionStorage.getItem("currentUser")? 
            JSON.parse(sessionStorage.getItem("currentUser") as string).token : null);
        }
    }
    })

3. On the login service, we import the jwt helper service and then inject it in the ctor:

    import { JwtHelperService } from '@auth0/angular-jwt';

    ...
    
    constructor(private httpBackend: HttpBackend, private jwtHelperService : JwtHelperService) { 
    }

And add a method to check if the user is authenticated:

    public isAuthenticated() : boolean {
        var token = sessionStorage.getItem("currentUser")? 
        JSON.parse(sessionStorage.getItem("currentUser") as string).token : null;
        
        if(this.jwtHelperService.isTokenExpired(token))
        {
        return false;
        }
        return true;
    }

4. Now create a CanActivateGuard

    ng g guard auth/auth

Inside the guard inject the login service and the router:

    export const authGuard = () => {
    const loginService = inject(LoginService);
    const router = inject(Router);

    if (loginService.isAuthenticated()) {
        return true;
    }
    return router.navigate(["login"]);
    };

In the app-routing we add to the routes we want to add the authorization guard:

    const routes: Routes = [
    { path: "dashboard", component: DashboardComponent, canActivate:[authGuard] },
        ...
    ];

# Role Based Authentication

1. In the .net project have the app user class have also a prop called Role of type string.
2. In the user service, fill in the prop with an if the user isInRoleAsync

    var applicationUser = await _applicationUserManager.FindByNameAsync(loginViewModel.Username);
    applicationUser.PasswordHash = null;

    if (await _applicationUserManager.IsInRoleAsync(applicationUser, "Admin"))
        applicationUser.Role = "Admin";
    else if (await _applicationUserManager.IsInRoleAsync(applicationUser, "Employee"))
        applicationUser.Role = "Employee";

3. Still in the user service, pass in a new claim with the role in the payload:

    new Claim(ClaimTypes.Role, applicationUser.Role)

4. In the angular app, in the guard class, pass in a jwtHelperService,  get the token, and check if the decoded token role is different from an expected role (still to be created)

    export const authGuard: CanActivateFn = (route : ActivatedRouteSnapshot) => {

    const loginService = inject(LoginService);
    const router = inject(Router);
    const jwtHelperService: JwtHelperService = inject(JwtHelperService);

    var token = sessionStorage.getItem("currentUser")? JSON.parse(sessionStorage.getItem("currentUser") as string).token : null;

    if (loginService.isAuthenticated() && jwtHelperService.decodeToken(token).role != route.data["expectedRole"]) {
        return true;
    }

    console.log(token)
    console.log(jwtHelperService.decodeToken(token).role)
    console.log("back to login")

    return router.navigate(["login"]);
    };

5. In the app routes module, add the data object containing the expected role prop:

    const routes: Routes = [
    ...
    { path: "dashboard", component: DashboardComponent, canActivate:[authGuard], data: {expectedRole: "Admin"} },
    ...
    ];

# Preventing CSRF (Cross site request forgery)
Its an attack to the website by making a request based on the users previously authenticated session.
Its only possible in case of cookie session authentication.
To prevent it we use a jwt token or cookie token + anti-forgery token.

1. To enable it on an angular project go to the login service, and in the login method:

        ...
        return this.httpClient.post<any>("/authenticate",loginViewModel, {responseType: "json", observe:"response" })
        .pipe(map(response => {
            if(response)
            {
                this.currentUserName = response.body.userName;
                sessionStorage.currentUser = JSON.stringify(response.body);
                sessionStorage.XSRFRequestToken = response.headers.get("XSRF-REQUEST-TOKEN");
            }
            return response.body;
        }))

2. On the projects service (or the service which methods we want to add the verification) add:

    insertProject(...){

        var requestHeaders = new HttpHeaders();
        requestHeaders.set("X-XSRF-TOKEN", sessionStorage.XSRFRequestToken);

        return... {headers: requestHeaders,...}
    }

# Preventing XSS (Cross site scripting)
Its an attack to the website by injecting malicious js into html elements of the app.

By default angular doesn't provide any sanitization for the html code in the template. but sanitizes any value inserted into the html elements using property binding, interpolation binding etc as they are untrusted by default.

domSanitizer.bypassSecurityTrustHtml - for injecting html code into innerHTML
domSanitizer.bypassSecurityTrustUrl - for injecting url into href
domSanitizer.bypassSecurityTrustResourceUrl - for injecting url into src

<br><br>

# Template driven forms
* They're suitable for simple forms with less nr of fields.
* They´re the default and are based on FormsModule
* ngModel is used for binding
* validation rules are written in the components template
* validation messages are defined and displayed in the components template
* they´re not unit testable

## Validations in Template Driven Forms

* required - specifies that the field is mandatory
* pattern - specifies regular expression
* minlength - min of chars to accept 
* maxlength - max of chars to accept. 

## Validation Properties in Template Driven Forms

* untouched - true if not focused at least once by the user
* touched - true if focused at least once by the user
* prestine - true if not modified at least once by the user
* dirty - true if modified at least once by the user
* valid - true if no validation errors
* invalid - true if validation errors
* errors

## Prepare form for validations
We can give the html a var name like so:

    <input #newProjectID="ngModel"

and then refer to that var name to for instance load a class conditionally:

    <div class="col-sm-8">
    <input #newProjectID="ngModel" type="text" id="txtNewProjectID" style="width:130px" class="form-control" placeholder="Project ID" name="ProjectID" required="required" pattern="^[0-9]*$" [(ngModel)]="newProject.projectID"
    [ngClass]="{'is-invalid': newProjectID.invalid && (newProjectID.dirty || newProjectID.touched || newForm.submitted),'is-valid': newProjectID.valid && (newProjectID.dirty || newProjectID.touched || newForm.submitted)}">
    </div>

The form tag can also receive a var:

    <form #newForm="ngForm" novalidate="novalidate">

## Custom Validations in Template Driven Forms
1. Create a validator directive class that extends from validator.
In the terminal:

    ng g directive ClientLocationStatusValidator

In the directive:

    @Input("appTeamSizeValidator") n: number | any = 0;

    validate(control: AbstractControl): ValidationErrors | null
    {
        let currentValue = control.value;
        let isValid = currentValue % this.n == 0;

        if (isValid)
        {
        return null; //valid
        }
        else
        {
        return { divisible: { valid: false } }; //indicates invalid
        }
    }

2. Add an input decorator with the name of the decorator that we´ll also put in the html elements

... maxlength="7" appTeamSizeValidator="5" #newTeamSize="ngModel"...

3. In the decorator @Directive add the selector and provides like so:

        @Directive({
        selector: '[appTeamSizeValidator]',
        providers: [{ provide: NG_VALIDATORS, useExisting: TeamSizeValidatorDirective, multi: true }]
        })

## Cross Field Custom Validations
Applies the validation to the form tag and not to the element

1. Create the directive

    ng g directive ClientLocationStatusValidator

2. In the validator, add the providers:

    @Directive( {
        selector: '[appClientLocationValidator]',
        providers: [{provide: NG_VALIDATORS, useExisting:ClientLocationValidatorDirective, multi: true}]
    })

3. Implement the interface Validator and on the validate method add the validation logic.

    export class ClientLocationStatusValidatorDirective implements Validator {
        ...
        validate(control:AbstractControl): ValidationErrors | null
        {
            let isValid = true;
            if(control.value.ClientLocation == 6...){
                return {clientLocationStatus: {valid: false}};
            }
            return null;
        }
    }

4. Apply the selector tag to the form ... appClientLocationValidator

5. In the component, check if the form contains validation errors:

        <span... *ngIf="newForm.invalid && newForm.errors?.clientLocationStatus"">Message of validation error
        </span>

## Async Custom Validations
Sometimes we cannot validate immediately, as it can depend on a api call for ex.
Implements the async validator.

<br><br>

# Reactive Forms

* [formGroup] and formControlName tags are used for binding
* Validation rules are written in the component
* are unit testable

Ex: Create a component and inside the component.ts we create: 

    export class SignUpComponent {
    
    signUpForm!: FormGroup;

    ngOnInit(){
        this.signUpForm = new FormGroup({
        firstName: new FormControl(null),
        lastName: new FormControl(null),
        email: new FormControl(null),
        mobile: new FormControl(null),
        dateOfBirth: new FormControl(null)
        });
    }
    }

and then on the template we must create the form and then bind it:

## Radio Buttons
Continuing on the form from before

On the component:

    ...
    gender: new FormControl(null)
    ...

On the html:

    <div class="form-group form-row">
    <label for="gender" class="col-md-4 col-form-label">Gender:</label>
    <div class="col-md-8">
        <div class="form-check-label form-check-inline">
        <input type="radio" name="gender" id="male" value="male" class="form-check-input" formControlName="gender">
        <label for="male" class="form-check-label">Male</label>
        </div>
        <div class="form-check-label form-check-inline">
        <input type="radio" name="gender" id="female" value="female" class="form-check-input" formControlName="gender">
        <label for="female" class="form-check-label">Female</label>
        </div>
         </div>
    </div>

## Dynamic radio buttons
The same example from before but dynamic. 

In the component we add the array with the options:

    genders = ["male","female"];

and in the html

        <div class="form-group form-row">
        <label for="gender" class="col-md-4 col-form-label">Gender:</label>
        <div class="col-md-8">
            <div class="form-check-label form-check-inline" *ngFor="let gender of genders">
            <input type="radio" name="gender" [id]="gender" [value]="gender" class="form-check-input" formControlName="gender">
            <label [for]="gender" class="form-check-label">{{gender}}</label>
            </div>
        </div>
    </div>

## Dynamic dropdown
Continuing the example from before:
Create a class country for we have a sample to populate the dropdown.

    export class Country {
    countryID : number = 0;
    countryName : string = "";

    constructor(countryIdParam:number, countryNameParam: string){
        this.countryID = countryIdParam;
        this.countryName = countryNameParam;
    }
}

Create a class to get the countries:

    export class CountriesService {

    constructor() { }

    getCountries() : Country[]
    {
        return [
        new Country(1, "India"),
        new Country(2, "UK"),
        new Country(3, "USA"),
        new Country(4, "Japan")
        ]
    }
    }

In the signup component inject the service and add a prop to hold the countries.

    ...
    countries: Country[] = [];

    ...
    ngOnInit()..
    this.countries = this.countriesService.getCountries();

    ...
    countryID: new FormControl(null),

in the html:

        <div class="form-group form-row">
        <label for="countryID" class="col-md-4 col-form-label">Country:</label>
        <div class="col-md-8">
            <select name="countryID" id="countryID" class="form-control" formControlName="countryID"></select>
            <option value="null">Please select</option>
            <option *ngFor="let country of countries" [value]="country.countryID">{{country.countryName}}</option>
        </div>
    </div>

## Checkbox
Add the formControl to the formGroup on the component:

    ngOnInit(){
    this.countries = this.countriesService.getCountries();
    this.signUpForm = new FormGroup({
        ...
      receiveNewsLetters: new FormControl(null)
    });
  }

and then on the html of the form:

    <div class="form-group form-row">
        <label class="col-md-4 col-form-label"></label>
        <div class="col-md-8">
        <input type="checkbox" name="receiveNewsletters" id="receiveNewsletters" class="form-control" value="true" formControlName="receiveNewsLetters">
        <label for="receiveNewsLetters" class="form-check-label">Receive Newsletters</label>
        </div>
    </div>

## valueChanges observabe
Whenever any form element value is changed we get a notification (if we subscribe to it). 

in the component:

    this.signUpForm.valueChanges.subscribe((value : any) =>{
      console.log(value);
    })

## setValue, patchValue, reset
* The set method overrides all the form elements in the form group. You must pass values for all form elements or else it'll throw.
* the path method updates the specified form element in the form group. You can pass only for the specified form elements.
* the reset method, can clear all the form elements if we don't specify which element must we clear. Generally the clear all elements is used after submitting a form.

In the html we crete a button to be able to submit: 

        <div class="card-footer">
            <button class="btn btn-success float-right">Create account</button>
        </div> 

and in the html of the form we must add the ngSubmit tag.

        <form [formGroup]="signUpForm" (ngSubmit)="onSubmitClick()">

and on the component:

        onSubmitClick(){
            this.signUpForm.reset({
                firstName: "Adam",
                lastName: "Smith"
            });
        }

## Nested Form Groups
We can create a form group inside another form group.
ex, on the component, we can have:

    personName: new FormGroup({
        firstName: new FormControl(null),
        lastName: new FormControl(null)}),

and then in the html we must add the parent form group identifier to the parent html div of both, like so:

    <div class="form-group form-row" formGroupName="personName">
        <label for="firstName" class="col-md-4 col-form-label">First Name:</label>
        ...
    </div>

    <div class="form-group form-row" formGroupName="personName">
        <label for="lastName" class="col-md-4 col-form-label">Last Name:</label>
        ...
    </div>

## Form Arrays
Sometimes we want to handle unlimited number of elements inside the form. For that purpose, we can use form arrays. In the example, we build in the form a form array where we can add unlimited skills where each one can have a level:

On the component:

        onAddSkill(){
            var formGroup = new FormGroup({
                skillName: new FormControl(null),
                level:new FormControl(null)
            });

            (<FormArray> this.signUpForm.get('skills')).push(formGroup);
        }

        onRemoveClick(index:number){
            (<FormArray> this.signUpForm.get('skills')).removeAt(index);
        }

On the html:

    <div class="form-group form-row">
        <label class="col-md-4 col-form-label">Skills:</label>
            <div class="col-md-8" formArrayName="skills">
            <div class="row" *ngFor="let skill of signUpForm.get('skills').controls; let i = index" [formGroupName]="i">

        <div class="col-5">
            <input type="text" name="skillName" id="skillName" placeholder="Skill Name" formControlName="skillName" class="form-control">
        </div>

        <div class="col-4">
            <select name="level" id="level" formControlName="level" class="form-control">
            <option value="null">Please Select</option>
            <option value="Beginner">Beginner</option>
            <option value="Intermediate">Intermediate</option>
            <option value="Professional">Professional</option>
            <option value="Expert">Expert</option>
            </select>
        </div>

        <div class="col-3">
            <button class="btn btn-danger" type="button" (click)="onRemoveClick(i)">Remove</button>
        </div>
    </div>

    <button class="btn btn-primary" type="button" (click)="onAddSkill()">Add Skill</button>
    </div>

## Form Builder
Meant for creating the form with easier syntax. It provides 3 methods.

        this.formBuilder.group({});
        this.formBuilder.control( defaultValue);
        this.formBuilder.array([]);

In our form group example we can shorten its syntax like so (on the form controls we can pass null):

        ngOnInit(){
            this.countries = this.countriesService.getCountries();
            this.signUpForm = this.formBuilder.group({
            personName: this.formBuilder.group({
                firstName: null,
                lastName: null}),
            email: null,
            mobile: null,
            dateOfBirth: null,
            gender:null,
            countryId: null,
            receiveNewsLetters: null,
            skills: this.formBuilder.array([])
            });
        };

## Validations in Reactive Forms
In reactive forms, validations are added in the component itself, rather than in the template. Also, the're unit testable.

* required 
* pattern
* minlength
* maxlength
* min
* max
* email

The validation properties in reactive forms are the same of the template driven ones (untouched,touched, prestine, dirty, etc)

Ex of the component:

        personName: this.formBuilder.group({
            firstName: [null, [Validators.required,Validators.minLength(2)]],
            lastName: null}),
        email: [null, [Validators.required, Validators.email]],

## Add Validation Error Messages

## Custom Validations
To create a custom validator we must:

1. Create a service:

    ng g service CustomValidators

2. Create a validator method that returns a validatorFn

    public minimumAgeValidator(minAge: number): ValidatorFn
    {
        return (control: AbstractControl): ValidationErrors | null =>
        {
        if (!control.value)
            return null; //return, if the date of birth is null

        var today = new Date();
        var dateOfBirth = new Date(control.value);
        var diffMilliSeconds = Math.abs(today.getTime() - dateOfBirth.getTime());
        var diffYears = (diffMilliSeconds / (1000 * 60 * 60 * 24)) / 365.25;

        if (diffYears >= minAge)
            return null; //valid
        else
            return { minAge: { valid: false } }; //invalid
        };
    }

3. Inject the service on the component to validate. To added it to the validators:

    dateOfBirth: [null, [Validators.required, this.customValidatorsService.minimumAgeValidator(18)]]

## Cross field Validations
To create a cross field validator, create a custom validator that takes in 2 params controlToValidate and controlToCompare. Then add it to the form validators.

        public compareValidator(controlToValidate: string, controlToCompare: string): ValidatorFn
        {
            return (formGroup: AbstractControl): ValidationErrors | null =>
            {
            if (!(formGroup.get(controlToValidate) as FormControl).value)
                return null; //return, if the confirm password is null

            if ((formGroup.get(controlToValidate) as FormControl).value == (formGroup.get(controlToCompare) as any).value)
                return null; //valid
            else
            {
                (formGroup.get(controlToValidate) as FormControl).setErrors({ compareValidator: { valid: false } });
                return { compareValidator: { valid: false } }; //invalid
            }
            };
        }

On the component:

    this.signUpForm = ...
    , {
        validators: [
            this.customValidatorsService.compareValidator("confirmPassword","password");
        ]
    }

## Submit Reactive Form

## Async Validations with Rest Call api
To check if some values already exist in a data base. Ex a signup form must look if email is already registered.

1. Create the action method and the endpoint in the asp.net app that searches the db for the email.

2. In the angular app, create the same method in the login or signup form:

    getUserByEmail(Email:string): Observable\<any>{
        this.httpClient = new HttpClient(this.httpBackend);
        return this.httpClient.get\<any>("/api/getUserByEmail/" + Email, {responseType: "json"});
    }

3. On a custom validator service, create the validator method:

    public DuplicateEmailValidator():AsyncValidatorFn
    {
        return (control: AbstractControl): Observable\<ValidationErrors | null> => {
            return this.loginService.getUserByEmail(control.value).pipe
            (map((existingUser:any)=>{
                if(existingUser != null)
                {
                    return {uniqueEmail:{valid:false}}
                }
                return null;
            }));
        }        
    }

4. On the component we must add the async validator to the form:

        email: [null, [Validators.required, Validators.email], [this.customValidatorService.DuplicateEmailValidator()], {updateOn:'blur'}],

5. On the html, add the message to present in case the validation fails.


# Component Communication

## Input Binding Parent to child

## Using ViewChild

## Using ViewChildren

## Output Binding Child to Parent

## Component communication using services

## Communication through Custom RxJS Observables

## RxJS Subject

## RxJS Behaviour Subject

## Sharing HTML Content from parent to child component

## Child to grand-child - using ContentChild

## Child to grand-child - using ContentChildren

## ElementRef

# Debugging Angular Code
Add debugger keyword
Build and run.
On the debugger of the browser now we can step into, step over, etc
It's like adding a breakpoint

# Gulp
Normally we must manually build the app with the ng build and then copy the dist files to the asp.net app.

1. Install Gulp cli

    npm install gulp-cli -g
    npm install gulp --save-dev

2. Create a gulpfile.js in the root of the angular app.
Inside add the following code:

    var gulp = require("gulp");

    gulp.task("Copy-dist-to-wwwroot", () => {
        return gulp.src("./dist/TaskManager/**/*")
        .pipe(gulp.dest(
            "C:\\Angular\\MvcTaskManager\\MvcTaskManager\\wwwroot"
        ));
    });

    gulp.task("default", ()=>{
        gulp.watch("./dist/TaskManager", gulp.series("Copy-dist-to-wwwroot"));
    });

3. on the terminal and on the app dir write:

    ng build --watch

4. Parallell to that terminal window, open another terminal window in the app dir and write "gulp"

Now everytime we change something, the --watch will recompile the folder and then gulp sends the dist contents to the wwwroot

<br><br>

# Life Cycle Hooks
A component or directive has a lifecycle which is managed by angular.
The change detection process identifies changes made by the user or dev and updates it.

@Component
Create Instance Order 
Ctor executes
OnChanges.ngOnChanges() executes automatically 
OnInit.ngOnInit() executes automatically
DoCheck.ngDoCheck() executes whenever an event occurs
AfterContentInit.ngAfterContentInit() executes after initialization of content
AfterContentChecked.ngAfterContentChecked() executes after change detection
AfterViewInit.ngAfterViewInit executes after initialization of view of the comp.
AfterViewChecked.ngAfterViewChecked() executes after change detection of the process of view of the comp.
OnDestroy.ngOnDestroy() executes when the user changes the route.

## NgOnChanges
Does not execute when there're no input properties.
Use to examine and change the incoming values.

## NgOnInit
Use to make api calls via services to fetch initial data from the db

## NgDoCheck
Use to write a custom version of the change detection process.

## NgAfterContentInit
Executes once in the lifetime of the component.
Use to manipulate the ContentChildren.

## NgAfterContentChecked
Executes every time after completion of change detection process of the content

## NgAfterViewInit
Executes once in the lifetime of the component.
Use to manipulate the ContentChildren.
Best to access ViewChild or ViewChildren

## NgAfterViewChecked
Executes every time after completion of change detection process of the template

## NgOnDestroy
Executes before removing the component of the dom.
Use to unsubcribe the observables that are subscribed in the ngOnInit. If we don't unsubscribe it may lead to memory leaks and performance issues.

<br><br>

# Custom Pipes
Pipe is a class that receives the value of the component property before rendering it to the dom.
Must be decorated with the @Pipe keyword.
It implements the PipeTransform interface that contains the transform method.

To create a pipe from the terminal

    ng g pipe NumberToWords

    @Pipe({
        name:'NumberToWords'
    })
    export class NumberToWords implements PipeTransform
    {
        transform(value:any, args?:any, args2?:any):any
        {
            ...
        }
    }

## Complex custom pipe
1. Create pipe

    ng g pipe Filter

2. In the pipe transform method:

    transform(value: Project[], searchBy:string, searchText: string):any{
        
        if( value == null){
            return value;
        }

        let resultArray = [];
        
        for (let item of value){
            
            if(String(item[searchBy]).toLowerCase().indexOf(searchText.toLowerCase()) >= 0){
                resultArray.push(item);
            }
        }

        return resultArray;
    }

3. On the component.html

        <div class="col-md-4" *ngFor="let project of projects | filter: searchBy : searchText; let i = index">
        </div>


## Pure pipes vs impure pipes
Pure pipe doesn't re-execute in case of any changes to the object properties, as does the impure.
Pure pipes are faster because they just check the ref instead of the object or actual elements.

    @Pipe({
        name:"pipeName",
        pure: false
    })


## Pagination using Pipes
Although we can do it in the client side, in real projects, if we have large datasets it´s recommended to do it server side.

1. Create a new pipe called paging

    ng g pipe Paging

2. In the method transform inside the pipe:

    transform(value: Project[], currentPageIndex: number, pageSize: number):any{

        if(value == null){
            return value;
        }

        let resultArray = [];
        for (let i = currentPage * pageSize; i < (currentPageIndex + 1) * pageSize; i++){

            if(value[i]){
                resultArray.push(value[i]);
            }
        }
        return resultArray;
    }

3. In the component add:

    currentPageIndex: number = 0;
    pages: any[] = [];
    pageSize :number = 3;

    calculateNoOfPages(){

        let filterPipe = new FilterPipe();
        var resultProjects = filterPipe.transform(this.projects, this.searchBy, this.searchText);
        var noOfPages = Math.ceil(resultProjects.length / this.pageSize);

        this.pages = [];
        for (let i = 0; i < noOfPages; i++){
            this.pages.push({pageIndex: i});
        }

        this.currentPageIndex = 0;
    }

4. On the component, on ngOnInit, after inserting a new project and deleting add the this.calculateNoOfPages()

5. In the projects component template, on the search box, add

    ...[(ngModel)]... (keyup)="onSearchTextKeyup($event)"


6. On the component:

    onSearchTextKeyup(event){

        this.calculateNoOfPages();
    }

7. On the template on the ngFor of the projects:

    *ngFor....| filter:....| paging : currentPageIndex : pageSize; let i = index"


8. Still on the template, we need to create the pages links:

        <div class="row">
            <div class="col-12">
                <ul class="pagination justify-content-center mt-1">
                    <li class="page-item" *ngFor="let page of pages" (click)="onPageIndexClicked(page.pageIndex)" [ngClass]=" {'active': : page.pageIndex == currentPageIndex}">
                        <a href="#" onclick="return false" class="page-link">{{page.pageIndex + 1}}</a>
                    </li>
                </ul>  
            </div>
        </div>


9. On the component:


    onPageIndexClicked(page.pageIndex){
        this.currentPageIndex = pageIndex;
    }

<br><br>

# Directives
Used to generate or manipulate elements in DOM programmatically.
They're classes that are invoked with an attribute or with a tag in the template.
Components are internally directives. The difference is that a component is associated with a template while a directive isn´t.


There are 2 types:
* Attribute directives (change the appearance of html like ngClass, used with [()])
* Structural directives (change the structure of html like ngFor, used with a *)


    @Directive({selector: '[attributeName]'}) //recommended prefix app...
    export class DirectiveName{
        constructor(){

        }
    }

The host is the name where the directive is invoked from meaning the element that will be manipulated.

We can also pass the inputs to the directive into the @input properties of the directive class.

## Custom Directives
To create a custom directive (example of display alert message)

1.  In the terminal run the command:

    ng g directive Alert

2. Go to the template and add a div tag:

        <div appAlert> //selector of the directive
        </div>

3. To access the host properties from the directive:

        export class AlertDirective{
            constructor(private elementRef: ElementRef){

            }

            ngOnInit(){
                this.elementRef.nativeElement.innerHTML = `
                <div class="alert alert-danger fade show" role="alert">
                    <span>Welcome</span>
                </div>
                `;
            }
        }

## Receive params using Input props
To be able to pass attributes to the host we need the input declaration in the directive:

    @Input("error") error:string;

and passing the error to the span:

            ngOnInit(){
                this.elementRef.nativeElement.innerHTML = `
                <div class="alert alert-danger fade show" role="alert">
                    <span>${this.error}</span>
                </div>
                `;
            }

Now on the host element:

    <div appalert [error]=" loginError "></div>


## HostListener
this decorator is used to handle an event of host element with a method of directive class

    @HostListener("eventName")
    methodName(){
        //some code
    }

1. On the same example, in the alert directive, we create 2 methods

    @HostListener("mouseenter", ["$event"])
    onMouseEnter(event){

        this.elementRef.nativeElement.querySelector(".alert").style.transform = "scale(1.1)";
    }

    @HostListener("mouseleave", ["$event"])
    onMouseLeave(event){

        this.elementRef.nativeElement.querySelector(".alert").style.transform = "scale(1)";
    }

    ngOnInit(){
        ...
        ...role="alert" style="transition: transform 0.5s..."
    }

## HostBinding
this decorator is used to bind a directive prop with an attribute of host element

1. In the same example, on the alert directive:

    @HostBinding("title") title:string;

    ngOnInit(){
        ...
        ...
        this.title = "Please try again!";
    }

## Renderer2
Its not recommended to write html inside directives because this way they´re not unit testable. It´s recommended to render the DOM using a class Renderer2.

abstract createElement(name:string, namespace?:string): any => used to create a new instance of a html tag

abstract createComment(value:string):any => used to add an html comment to the DOM.

abstract createText(value:string):any => used to add plain text to the DOM

abstract appendChild(parent:any, newChild:any) : void => used to add the child element to the parent element

abstract insertBefore(parent:any, newChild:any, refChild:any) : void => used to add a new element inside the existing element before the ref child 

abstract setAttribute(el:any,name:string,value:string,namespace?:string):void => used to add an attribute to the element

abstract removeAttribute(el:any,name:string,namespace?:string):void => removes an attribute from the element

abstract addClass(el:any,name:string):void => adds a css class to the element

abstract removeClass(el:any,name:string):void => removes a css class from the element

abstract setStyle(el:any, style:string, value:any, flags?: RendererStyleFlags2):void => adds inline css style to the element

abstract listen(target: any, eventName:string, callback:(event|any) =>boolean | void): () => void
Used to add an event to the element

1. In the same example from earlier let's change the html inside the directive with the help of the renderer2 class. He had this code:

        ngOnInit(){
            this.elementRef.nativeElement.innerHTML = `
            <div class="alert alert-danger fade show" role="alert">
                <span>${this.error}</span>
            </div>
            `;
        }

2. First, we must inject renderer2 in the ctor and create 3 vars, each for each element:

    constructor(... , private renderer2 : Renderer2)

    divElement: any;
    spanElement: any;
    spanText: any;

        ngOnInit(){
            this.divElement = this.renderer2.createElement("div");
            this.renderer2.setAttribute(this.divElement,"role","alert");
            this.renderer2.setAttribute(this.divElement,"class","alert alert-danger fade show");
            this.renderer2.setStyle(this.divElement,"transition","transform .05s");

            this.spanElement = this.renderer2.createElement("span");
            this.renderer2.setAttribute(this.spanElement,"class","message");

            this.spanText = this.renderer2.createText(this.error);
            this.renderer2.appendChild(this.spanElement,this.spanText);

            this.renderer2.appendChild(this.divElement, this.spanElement);

            this.elementRef.nativeElement.appendChild(this.divElement);
        }

        onMouseEnter(event){
            this.renderer2.setStyle(this.divElement, "transform","scale(1.1)");
        }

        onMouseLeave(event){
            this.renderer2.setStyle(this.divElement, "transform","scale(1)");
        }

## Custom Structural Directive
For ex, we want to create a directive similar to *ngFor but that duplicates a nr of times a certain html tag:

1. On a terminal:

    ng g directive Repeater

2. On the directive class Repeater:

        @Input("appRepeater") n: number;

        constructor(private viewContainerRef: ViewContainerRef, private templateRef: TemplateRef<any>){

            this.viewContainerRef.clear();

        }

        ngOnInit(){
            for( let i  = 0; i < this.n; i++){
                this.viewContainerRef.createEmbeddedView(this.templateRef,{ $implicit:i});
            }
        }


3. On the template:

        <div *appRepeater="5; let i ">{{i}}</div>

<br><br>

# Advanced Routing

## Route parameters

1. User passes a param value from browser's URL
2. Angular router assigns value to the parameter

Receiving route params in component class:

    constructor(private activatedRoute:ActivatedRoute)
    {

    }

    ngOnInit(){

        this.mySubscription = this.activatedRoute.params.subscribe((params)=>{
            params["paramName"] //do something with the parameter
        });
    }

3.  In the appRouting module add in the Routes:

    ...,

    {path:"projects/view/:projectid",
    component: ProjectsDetailsComponent, 
    canActivate:[CanActivateGuardService], 
    data:{expectedRole:"Admin"}}

4. In the projects template:

        <a class="btn btn-primary" [routerLink]="['/projects','view','project.projectID]">Details</a>

5. Now on the single details component:

        export class ProjectDetailsComponent implements OnInit{

            project: Project;
            routeParamsSubscription: Subscription;

            constructor(private activatedRoute:ActivatedRoute, private projectsService:ProjectsService){
                
                this.project = new Project();
            }

            ngOnInit(){
                this.routeParamsSubscription = this.activatedRoute.params.subscribe((params)=>{
                    let pid = params["projectid"];
                    this.projectsService.getProjectById(pid).subscribe((proj:Project) => {
                        this.project = proj;
                    });
                });
            }

            ngOnDestroy(){
                this.routeParamsSubscription.unsubscribe();
            }
        }

## Child Routes

    {path:"parentRoute",children:[
        {path:"childRoute1", component:Child1Component},
        {path:"childRoute2", component:Child2Component}
    ]}

## Nested Routes
In large apps we need a way to have multiple files with their own routes.To do that we can:

1. Create an admin module to hold the new routes:

    ng g module AdminRouting

2. Copy the routes from the previous file into this new module (and remove them from the original file):

    const routes: Routes = [
        {...},
        {...},
    ]

3. On the new module, on imports:

    @NgModule({
        imports: [
            RouterModule.forChild(routes)
        ]
        exports:[RouterModule]
    })

## Router Events
Angular router has 16 events that execute in a sequence:

* NavigationStart
* RouteConfigLoadStart
* RouteConfigLoadEnd
* RoutesRecognized
* GuardsCheckStart
* ChildActivationStart
* ActivationStart
* GuardsCheckEnd
* ResolveStart
* ResolveEnd
* ChildActivationEnd
* ActivationEnd
* NavigatonEnd
    * NavigationCancel
    * NavigationError
* Scroll

To activate the routing tracing, on the app-routing module, on the imports enable tracing to true:

        imports: [RouterModule.forRoot(routes, {useHash:true, enableTracing: true})]
    
## Subscribe to the routing events (server side logging)

1. On the .net project, create a new controller RouterLoggerController;

2. On the new controller:

    private readonly IHostingEnvironment _hostingEnvironment;

    public RouterLoggerController(IHostingEnvironment hostingEnvironment)
    {
        _hostingEnvironment = hostingEnvironment;
    }

    [HttpPost("api/routerlogger")]
    public IActionResult Index()
    {
        string logMessage = null;
        using (StreamReader streamReader = new StreamReader(Request.Body,Encoding.ASCI))
        {
            logMessage = streamReader.ReadToEnd() + "\n";
        }
        string filePath = _hostingEnvironment.ContentRootPath + "\\RouterLogger.txt";
        Sytem.IO.File.AppendAllText(filePath, logMessage);
        return Ok();
    }

3. Create a new service in the angular app:

    ng g service RouterLogger

4. In the service:

    private httpClient:HttpClient;
    currentUserName: string = null;


    constructor(private httpBackend: HttpBackend){

    }

    public log(logMsg:string): Observable<any>{

        this.httpClient = new HttpClient(this.httpBackend);
        return this.httpClient.post("/api/routerlogger",logMsg, 
        { headers: new HttpHeaders().set("content-type","text/plain")}
        );
    }

5. On the app component, inject the logger service:

    constructor(...,private routerLoggerService: RouterLoggerService, private router: Router)
    {

    }

    ngOnInit(){
        this.router.events.subscribe((event)=> {
            if (event instanceof NavigationEnd){
                let userName = (this.loginService.currentUserName)?
                this.loginService.currentUserName: "anonymous";

                let logMsg = new Date().toLocaleString() + ":" + userName + 
                " navigates to " + event.url;

                this.routerLoggerService.log(logMsg).subscribe();
            }
        });
    }

## canDeactivateGuard
In case there's a form an the user fills it but then changes the page, instead of immediate redirection, the user should be warned that it will loose whatever he already input.

1. create a guard service:

    ng g service CanDeactivateGuard

2. In the guard service


    export interface CanComponentDeactivate{
        canLeave: boolean;
    }

3. Whatever the component we want to guard, open it and implement the interface created:

    ...export class SignUpComponent implements OnInit, CanComponentDeactivate{

        ...
        canLeave: boolean = true;
        ...
    }

    //updating the canLeave prop in case some change was made in the form
    this.signUpForm.valueChanges.subscribe(
        (value) => {
            this.canLeave = false;
        }
    );

    //updating the onSubmitClick()

    this.canLeave = true;

4. On the guard:

    export class CanDeactivateGuardService implements CanDeactivate<CanComponentDeactivate>{
        
        canDeactivate(component: CanComponentDeactivate){

            if(component.canLeave == true){
                return true; //user can leave the current route
            }
            return confirm("Do you want to discard changes?");
        }
    }

# Animations
Provide ilusion of motion. Improve user experience.
Are based on css animations.

## Angular animation api.

    trigger("someanimation", [])

    transition("state1 <=> state2",[])

    group([query(...), query(...)]) //used to group-up multiple animations parallely

    query("css selector") //to select elements to animate

    style({property: "start value"}) //contains a set of css properties

    animate("1s", style(property:"value")) //represents animation that specifies time duration

## Order:

1. trigger
    2. transition
        3. query
            4. style


## Fade Animation
in an animations file my-animations.ts

     export const fadeAnimation = 
        trigger("routeAnimations",[
            transition("* <=> *", [ //means from any page to any page
                query(":enter,:leave",
                style({position:"absolute", width:"98%"}),
                {optional:true}),

                group([
                    query(":enter", [
                        style({opacity:0}),
                        animate("0.6s", style({opacity:"1"}))
                    ]), {optional:true}
                ])

                group([
                    query(":leave", [
                        style({opacity:1}),
                        animate("0.6s", style({opacity:"0"}))
                    ]), {optional:true}
                ])
            ]) 
        ]);

in the target component we must import the animation constant:

    @Component({
        selector...
        ...
        animations:[fadeAnimation]
    })

    getState(outlet){
        //check if some component is loaded in the outlet if so return url if not return none
        return outlet.isActivated? 
        outlet.activatedRoute.snapshot.url[0].path :
        "none";
    }

in the target template we add the animation tag and pass in the outlet state to the method:

    <div class="container-fluid" [@routeAnimations] = "getState(outlet)">
        <router-outlet #outlet="outlet"></router-outlet>
    </div>

## Slide up animation
in an animations file my-animations.ts

     export const slideUpAnimation = 
        trigger("routeAnimations",[
            transition("* <=> *", [ //means from any page to any page
                query(":enter,:leave",
                    style({position:"absolute", width:"98%"}),
                    {optional:true}),

                    group([
                        query(":enter", [
                            style({transform:"translateY(100%)"}),
                            animate("0.6s", style({transform:"translateY(0%)"}))
                        ]), {optional:true}
                    ])

                    group([
                        query(":leave", [
                            style({transform:"translateY(0%)"}),
                            animate("0.6s", style({transform:"translateY(-100%)"}))
                        ]), {optional:true}
                    ])
            ]) 
        ]);

in the target component we must import the animation constant:

    @Component({
        selector...
        ...
        animations:[slideUpAnimation]
    })

## Zoom-up animation
in an animations file my-animations.ts

     export const zoomUpAnimation = 
        trigger("routeAnimations",[
            transition("* <=> *", [ //means from any page to any page
                query(":enter,:leave",
                    style({position:"absolute", width:"98%"}),
                    {optional:true}),

                    group([
                        query(":enter", [
                            style({transform:"scale(0) translateY(100%)"}),
                            animate("0.6s", style({transform:"scale(1) translateY(0%)"}))
                        ]), {optional:true}
                    ])

                    group([
                        query(":leave", [
                            style({transform:"scale(1) translateY(0%)"}),
                            animate("0.6s", style({transform:"scale(0) translateY(-100%)"}))
                    ]), {optional:true}
                ])
            ]) 
        ]);

in the target component we must import the animation constant:

    @Component({
        selector...
        ...
        animations:[zoomUpAnimation]
    })


## Slide-left slide right animation
to be able to slide left or right as the elements are sequentially. for that we need to pass in the data from the app routing that allows the animation to know.

in the app-routing file in the const routes, add to each path the data object like so:

        {path:...,redirectTo:....,data:{linkIndex:1}}
        {path:...,redirectTo:....,data:{linkIndex:2}}
        {path:...,redirectTo:....,data:{linkIndex:3}}
        ...

do that for all the routes in all the files.

and in the app component getState we will pass the linkIndex:

    
        getState(outlet){
            ...
            .path && outlet.activatedRouteData["linkIndex"]:"none";
        }

in an animations file my-animations.ts

        
        function slideLeft(){
            return [
            query(":enter,:leave",
                style({position:"absolute", width:"98%"}),
                {optional:true}),

                group([
                    query(":enter", [
                        style({transform:"scale(0) translateX(100%)"}),
                        animate("0.6s", style({transform:"scale(1) translateX(0%)"}))
                    ]), {optional:true}
                ])

                group([
                    query(":leave", [
                        style({transform:"scale(1) translateX(0%)"}),
                        animate("0.6s", style({transform:"scale(0) translateX(-100%)"}))
                    ]), {optional:true}
                ])
            ];
        }
        
        function slideRight(){
            return [
            query(":enter,:leave",
                style({position:"absolute", width:"98%"}),
                {optional:true}),

                group([
                    query(":enter", [
                        style({transform:"scale(0) translateX(-100%)"}),
                        animate("0.6s", style({transform:"scale(1) translateX(0%)"}))
                    ]), {optional:true}
                ])

                group([
                    query(":leave", [
                        style({transform:"scale(1) translateX(0%)"}),
                        animate("0.6s", style({transform:"scale(0) translateX(100%)"}))
                    ]), {optional:true}
                ])
            ];
        }


        export slideLeftOfRightAnimation = 
            trigger("routerAnimations", [
                transition("0 => 1", slideLeft()),
                transition("0 => 2", slideLeft()),
                transition("0 => 3", slideLeft()),
                transition("0 => 4", slideLeft()),
                transition("0 => 5", slideLeft()),
                transition("0 => 6", slideLeft()),

                transition("1 => 0",slideRight()),
                transition("1 => 2",slideLeft()),
                transition("1 => 3",slideLeft()),
                transition("1 => 4",slideLeft()),
                transition("1 => 5",slideLeft()),
                transition("1 => 6",slideLeft()),

                transition("2 => 0",slideRight()),
                transition("2 => 1",slideRight()),
                transition("2 => 3",slideLeft()),
                transition("2 => 4",slideLeft()),
                transition("2 => 5",slideLeft()),
                transition("2 => 6",slideLeft()),

                transition("3 => 0",slideRight()),
                transition("3 => 1",slideRight()),
                transition("3 => 2",slideRight()),
                transition("3 => 4",slideLeft()),
                transition("3 => 5",slideLeft()),
                transition("3 => 6",slideLeft()),

                transition("4 => 0",slideRight()),
                transition("4 => 1",slideRight()),
                transition("4 => 2",slideRight()),
                transition("4 => 3",slideRight()),
                transition("4 => 5",slideLeft()),
                transition("4 => 6",slideLeft()),

                transition("5 => 0",slideRight()),
                transition("5 => 1",slideRight()),
                transition("5 => 2",slideRight()),
                transition("5 => 3",slideRight()),
                transition("5 => 4",slideRight()),
                transition("5 => 6",slideLeft()),

                transition("6 => 0",slideRight()),
                transition("6 => 1",slideRight()),
                transition("6 => 2",slideRight()),
                transition("6 => 3",slideRight()),
                transition("6 => 4",slideRight()),
                transition("6 => 5",slideRight()),
            ]);

## Keyframe animation
add different milestones in the duration of the animation.


        export const keyframeAnimation = 
        trigger("routeAnimations",[
            transition("* <=> *", [ //means from any page to any page
                query(":enter,:leave",
                    style({position:"absolute", width:"98%"}),
                    {optional:true}),

                    group([
                        query(":enter", [
                            animate("1s", keyframes([
                                style({offset:0,transform:"scale(0,5) translateX(-100%)","transform-origin":"center left "}),
                                style({offset:0.3,transform:"scale(0,5) translateX(30%)"}),
                                style({offset:0.7,transform:"scale(0,5) translateX(30%)"}),
                                style({offset:1,transform:"scale(1) translateX(0%)"})
                            ])
                            )
                        ]), {optional:true}
                    ])

                    group([
                        query(":leave", [
                            animate("1s", keyframes([
                                style({offset:0,transform:"scale(1) translateX(-100%)","transform-origin":"center right "}),
                                style({offset:0.3,transform:"scale(0,5) translateX(0%)"}),
                                style({offset:0.7,transform:"scale(0,5) translateX(0%)"}),
                                style({offset:1,transform:"scale(1) translateX(100%)"})
                            ])
                            )
                        ]), {optional:true}
                    ])
            ]) 
        ]);

# Feature Modules
There are 4 types of feature modules:

* Domain feature modules - represents a domain (employee, admin, finance, etc)
* Lazy loaded feature modules - domain feature modules that are lazy loaded
* Routing feature modules - define routes, add guards to them.
* Shared feature modules - share a common set of directives and pipes

## Folder structure

* moduleFolder
    * components
    * directives
    * guards
    * interceptors
    * models
    * pipes
    * services

## Lazy loading modules
Means that we're only loading the module once the user needs it.

In real apps all the domain feature modules are lazy loaded.

To activate lazy loading of a module (ex: admin module):

0. Open tsconfig.json and on modules: esNext

1. In the admin-routing, delete the path "admin" and leave it "";
2. Go to the app-routing module and add a path with admin route with the load children property:


    ...
    {path: "admin", loadChildren: ()=> import("./admin/admin.module").then( m => m.AdminModule)}

3. In the app.module, remove the import of AdminModule

4. In the admin.module remove the declaration and export property of the about component and add it to the app-module declarations

## Preloading strategy of lazy loading modules
When the browser is idle, it preloads the lazy loading modules.

In order to enable it:

1. Go the the app routing module, in the imports of the ngModule:

    @NgModule({
        imports: [RouterModule.forRoot(routes, {useHash:true, enableTracing:false, preloadingStrategy:PreloadAllModules})]
    })

# Dynamic Components
To be able to load components at runtime based on the actions of the user.
For this we need 2 classes:

* ViewContainerRef = Represents a specific place in the DOM where the component is to be loaded
* ComponentFactoryResolver = Loads the specified component dynamically.


1. In the terminal, create a component:

    ng g component Countries
    ng g component ClientLocations
    ng g component TaskPriorities
    ng g component TaskStatus
    ng g component Masters

2. In the routes module add the route:

    {path: "masters", component: MastersComponent}


3. On the masters component:

    export class MastersComponent implements OnInit {
        
        masterMenuItems = [
            { itemName:"Countries",displayName:"Countries", component: CountriesComponent},
            { itemName:"ClientLocations",displayName:"Client Location", component:ClientLocationsComponent},
            { itemName:"TaskPriorities",displayName:"Task Priorities", component:TaskPrioritiesComponent},
            { itemName:"TaskStatus",displayName:"Task Status", component:TaskStatusComponent}
            ];

        activeItem:string = "";+
        tabs = [];

        @ViewChildren(ComponentLoaderDirective)
        componentLoaders:QueryList<ComponentLoaderDirective>;

        constructor(private componentFactoryResolver:ComponentFactoryResolver){

        }

        menuItemClick(clickedMasteMenuItem:any){
            this.activeItem = clickedMasterMenuItem.itemName;

            let matchingTabs = this.tabs.filter((tab)=> {
                return tab.itemName == clickedMasteMenuItem.itemName
            });

            if (matchingTabs.length == 0){
                this.tabs.push({
                    tabIndex: this.tabs.length,
                    itemName: clickedMasterMenuItem.itemName,
                    displayName: clickedMasterMenuItem.displayName
                });

                setTimeout(()=> {
                    var componentLoadersArray = this.componentLoaders.toArray();
                    var componentFactory = this.componentFactoryResolver.resolveComponentFactory(clickedMasterMenuItem.component);

                    var viewContainerRef = componentLoadersArray[this.tabs.length -1].viewContainerRef;
                    
                    var componentRef = viewContainerRef.createComponent(componentFactory);

                    if(clickedMasterMenuItem.component.name == "CountriesComponent"){
                            
                            var componentInstance = componentRef.instance as CountriesComponent;
                            componentInstance.message = "Hello to Countries";
                    }

                }, 100);
            }
        }

        onCloseClick(clickedTab:any){
            clickedTab.viewContainerRef.remove();
            this.tabs.splice(this.tabs.indexOf(clickedTab),1);

            if(this.tabs.length > 0){
                this.activeItem = this.tabs[0].itemName;
            }
        }
    }

4. On the master template:

        <div class="row">
            <div class="col-md-2">
                <div class="list-group">
                    <a href="#" class="list-group-item list-group-item-action" onclick="return false" *ngFor="let masterMenuItem of masterMenuItems" [ngClass]="{'active':activeItem == masterMenuItem.itemName}" (click)="menuItemClick(masterMenuItem)">
                    {{masterMenuItem.displayName}}
                    </a>
                </div>
            </div>
            <div class="col-md-8">
                <ul class="nav nav-tabs" role="tablist">
                    <li class="nav-item" *ngFor="let tab of tabs">
                        <a class="nav-link" data-toggle="tab" role="tab" [href]=" '#' + tab.itemName" [ngClass]="{ 'active': activeItem == tab.itemName}" (click)="activeItem = tab.itemName">
                        {{tab.displayName}}
                        <span class="fa fa-window-close" (click)="onCloseClick(tab)">
                        </span>
                        </a>
                    </li>
                </ul>

                <div class="tab-content">
                    <div class="tab-pane fade show" role="tabpanel" *ngFor="let tab of tabs" [id]="tab.itemName" [ngClass]="{ 'active': activeItem == tab.itemName}">
                        <ng-template appComponentLoader>
                        </ng-template>
                    </div>
                </div>
            </div>
        </div>


5. Create the component loader directive:

    ng g directive ComponentLoader

6. In the module that we want to load the dynamic components, we must import them by:


    imports: [
        ...
        entryComponents: [
            CountriesComponent,
            ClientLocationComponent,
            TaskPrioritiesComponent,
            TaskStatusComponent
        ]
    ]

7.  On the componentLoader directive inject the view container ref service in the ctor:

    constuctor(public viewContainerRef: ViewContainerRef){

    }

# Unit Testing

* jasmine => used to define test cases
* protractor => used to execute test cases
* karma => used to execute test cases in multiple browsers

The test cases should be defined in the .spec.ts file of each component
To start unit test: ng test ...
To define a test case go to the spec.ts file and add:

    import { TestBed } from "@angular/core/testing"

    //heading for the tests
    describe("Login component testing", ()=>{
        beforeEach(()=>{
            TestBed.configureTestingModule({
                declarations:[LoginComponent],
                imports:[...]
            }).compileComponents();
        });

        it("Login - Success", ()=>{
            //here we define the tc logic
            var comp = TestBed.createComponent(LoginComponent).componentInstance
            comp.email = "...";
            comp.password = "...";
            comp.onLoginClick(new NgForm([],[]));
            expect(comp.loginStatus).toBe(true);
        });
    });

## Angular Zones
It's a memory area. Each component will execute on its own zone.

To not update every time the data binding items we can envelope the piece of code to a run outside zone snippet:

    constructor(@inject(NgZone) private zone: NgZone){
        this.zone.runOutsideAngular(()=>{
            setInterval(()=>{
                this.n = this.n +1;
            },300);
        });
    }

This will continue to calculate but will not refresh the component's ui. It only updates when some other event is raised.

# Angular Material
It's a UI component library to build ui's with standard of Google Material design.


