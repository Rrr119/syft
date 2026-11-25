extern const char *syft_03_identity(void);
int main(void) {
    return syft_03_identity()[0] == 's' ? 0 : 1;
}
