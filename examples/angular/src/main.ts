import {provideHttpClient} from '@angular/common/http';
import {bootstrapApplication} from '@angular/platform-browser';
import {AppComponent} from './app.component';

bootstrapApplication(AppComponent, {providers: [provideHttpClient()]}).catch(
  () => {
    document.body.textContent = 'The sample could not start. Please reload.';
  }
);
