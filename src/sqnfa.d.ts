import { Result } from "./result";

export interface Handler {
  handle(password: string): Result;
  name: string;
}
